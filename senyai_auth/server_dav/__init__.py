# import os
from __future__ import annotations
from typing import NamedTuple, NewType, TypedDict, NotRequired
from os import stat_result, getenv, utime, scandir
from os.path import splitext
from stat import S_ISDIR, S_ISREG, S_IFCHR
from base64 import b64decode
from collections import defaultdict
from collections.abc import Callable, Awaitable
from urllib.parse import unquote, quote
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from starlette.applications import Starlette
from starlette.responses import Response, FileResponse
from starlette.requests import Request
from starlette.routing import Route
from starlette.types import Scope, Receive, Send
from starlette.datastructures import URL
import aiofiles
import aiofiles.base
import aiofiles.os
from pathlib import Path
from mimetypes import types_map
from httpx2 import AsyncClient, NetworkError
from contextlib import asynccontextmanager
from time import monotonic
from asyncio import Future, create_task, sleep, get_running_loop
import httpcore  # needed for _drop_privileges
import anyio._backends._asyncio  # needed for _drop_privileges
import anyio._core._fileio  # needed for _drop_privileges
from .afs import copy, delete
from .. import __version__

ET.register_namespace("D", "DAV:")
ET.register_namespace("Z", "urn:schemas-microsoft-com:")

# viewing html in web browser could execute 'delete' dav request for example
mimetypes_web = {
    **types_map,
    ".htm": types_map[".txt"],
    ".html": types_map[".txt"],
    ".js": types_map[".txt"],
    ".log": types_map[".txt"],
    ".mjs": types_map[".txt"],
    ".svg": types_map[".txt"],
}
mimetypes_dav = {
    **types_map,
    ".log": types_map[".txt"],
}


def _mimetype(display_name: str, mimetypes: dict[str, str]) -> str:
    ext = splitext(display_name)[1].lower()
    return mimetypes.get(ext, "application/octet-stream")


def _human_readable_size(size: int | float) -> str:
    if size < 1024:
        return f"{size} B"
    size /= 1024.0
    for unit in ["KiB", "MiB", "GiB", "TiB", "PiB"]:
        if size < 1024.0 or unit == "PiB":
            break
        size /= 1024.0
    return f"{size:.2f} {unit}"


class DavSettings(NamedTuple):
    path: str = "."
    realm: str = "Storage"
    api_url: str = "http://127.0.0.1:8000"
    drop_privileges_user: str | None = None


# path without slash at the beginning and at the end
DAVPath = NewType("DAVPath", str)
# must start with `Bearer `. goes as Authorization header to api backend
Bearer = NewType("Bearer", str)
type Stats = list[tuple[str, stat_result]]

ONE_MONTH = 30 * 24 * 60 * 60
PERMISSIONS_NAME = "permissions.txt"
PERMISSIONS_PATH = Path(PERMISSIONS_NAME)


def _get_settings() -> DavSettings:
    import json

    settings_path = getenv("AUTH_DAV_SETTINGS_PATH", "settings_dav.json")
    try:
        with open(settings_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}
    return DavSettings(**data)


class Node:
    __slots__ = ("children", "can_write", "is_leaf")

    def __init__(self) -> None:
        self.children: defaultdict[str, Node] = defaultdict(Node)
        self.can_write = False
        self.is_leaf = False

    def __repr__(self) -> str:
        return (
            f"<{type(self).__name__} {dict(self.children)}"
            f"{' leaf' if self.is_leaf else ''} can_write={self.can_write}>"
        )


def _parse_rfc1123(text: str) -> float | None:
    try:
        # we expect text to always end with ' GMT' so we replace the timezone
        return (
            datetime.strptime(text, "%a, %d %b %Y %H:%M:%S %Z")
            .replace(tzinfo=timezone.utc)
            .timestamp()
        )
    except Exception:
        pass


class ResponseKwargs(TypedDict):
    content: NotRequired[str]
    status_code: int
    headers: NotRequired[dict[str, str]]
    media_type: NotRequired[str]


class Permissions:
    def __init__(self, paths: list[str]) -> None:
        self._root = root = Node()
        self._paths = paths
        for path_rw in paths:
            node = root
            path, sep, rights = path_rw.rpartition(":")
            if not sep:
                path, rights = rights, "r"
            path = path.strip("/")
            if path:  # without this check root can't become leaf
                for item in path.split("/"):
                    node = node.children[item]
            node.can_write |= rights == "w"
            node.is_leaf = True

    def closest_node(self, path: DAVPath) -> Node:
        node = self._root
        for item in path.split("/"):
            if item in node.children:
                node = node.children[item]
            else:
                return node
        return node

    def has_write_access(self, path: DAVPath) -> bool:
        node = self.closest_node(path)
        return node.is_leaf and node.can_write

    def has_read_access(self, path: DAVPath) -> bool:
        return self.closest_node(path).is_leaf

    def can_traverse(self, path: DAVPath) -> bool:
        return (
            not path
            or self.closest_node(path) is not self._root
            or self._root.is_leaf
            or path == PERMISSIONS_NAME
        )

    def list_children(self, path: DAVPath) -> tuple[Node, list[str] | None]:
        """
        Returns: Closest node, optional list of children that
                 user has permissions to
        """
        node = self._root
        if path:
            for item in path.split("/"):
                if item in node.children:
                    node = node.children[item]
                else:
                    return node, None
        return node, list(node.children)

    def txt(self) -> str:
        try:
            return self._txt
        except AttributeError:
            self._txt = "\n".join(f"* {path}" for path in self._paths)
        return self._txt

    def stat(self) -> stat_result:
        return stat_result((S_IFCHR, 0, 0, 0, 0, 0, len(self.txt()), 0, 0, 0))

    def __repr__(self) -> str:
        return f"{super().__repr__()[:-1]} {self._root}>"


def _drop_privileges(username: str) -> None:
    import pwd, os

    pw = pwd.getpwnam(username)
    target_uid = pw.pw_uid
    target_gid = pw.pw_gid
    os.setgroups([])
    os.setgid(target_gid)
    os.setuid(target_uid)


async def _api_bearer_for(
    api_client: AsyncClient,
    username: str,
    password: str,
) -> Bearer | None:
    token_res = await api_client.post(
        "/token",
        data={"username": username, "password": password},
    )
    if token_res.status_code != 200:  # login and password are invalid.
        return None

    token = token_res.json()
    return Bearer(
        f"{token['token_type'].capitalize()} {token['access_token']}"
    )


async def _api_permissions_for(
    api_client: AsyncClient, bearer: Bearer
) -> Permissions | None:
    """
    returns: `None` when not authorized (implicitly 401 error)
             or valid `Permissions`
    """
    permissions_res = await api_client.get(
        "/ldap/roles/storage", headers={"Authorization": bearer}
    )
    if permissions_res.status_code == 200:
        return Permissions(permissions_res.json())


class SenyaiDAV:
    def __init__(self, settings: DavSettings) -> None:
        self._settings = settings
        self._path = Path(settings.path)
        self._css = (
            Path(__file__)
            .with_name("webdav.css")
            .read_text()
            .replace("$VERSION", __version__)
        )

        self._methods: dict[
            str,
            Callable[
                [Path, DAVPath, Request, Permissions], Awaitable[Response]
            ],
        ] = {
            "PROPFIND": self.propfind,
            "GET": self.get,
            "HEAD": self.head,
            "PUT": self.put,
            "DELETE": self.delete,
            "MKCOL": self.mkcol,
            "COPY": self.copy,
            "MOVE": self.move,
            "LOCK": self.lock,
            "UNLOCK": self.unlock,
            "PROPPATCH": self.proppatch,
        }
        self._response_options = Response(
            headers={
                "DAV": "1, 2",
                "Allow": "OPTIONS, " + ", ".join(self._methods),
                "Content-Length": "0",
            },
            status_code=200,  # WebDAV likes 200
        )
        self._response_authentication_required = Response(
            content="Authentication required",
            status_code=401,
            # Info: we can only use Basic Authentication, because
            #       it is the one that shows username/password dialog
            headers={"WWW-Authenticate": f'Basic realm="{settings.realm}"'},
        )
        self._kwargs_no_permissions_write: ResponseKwargs = {
            "content": "Write permission denied",
            "status_code": 403,
            "headers": {"Content-Type": "text/plain", "DAV": "1"},
        }
        error = ET.Element("{DAV:}error")
        ET.SubElement(error, "{DAV:}privilege")
        ET.SubElement(error, "{DAV:}read")
        self._kwargs_no_permissions_propfind: ResponseKwargs = {
            "content": ET.tostring(
                error, encoding="unicode", xml_declaration=True
            ),
            "media_type": 'application/xml; charset="utf-8"',
            "status_code": 403,
        }
        self._kwargs_no_permissions_read: ResponseKwargs = {
            "content": "403 Read permission denied",
            "status_code": 403,
        }
        self._kwargs_not_found: ResponseKwargs = {
            "content": "404 Not Found",
            "status_code": 404,
        }
        self._response_api_failure = Response(
            content="Authentication backend is down", status_code=503
        )
        self._bearer_cache: dict[
            tuple[str, str], tuple[float, Future[Bearer | None]]
        ] = {}
        self._permissions_cache: dict[
            Bearer, tuple[float, Future[Permissions | None]]
        ] = {}

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":  # websocket or something
            return
        response = await self.handle(Request(scope, receive))
        await response(scope, receive, send)

    async def _permissions_for(
        self, bearer: Bearer, now: float
    ) -> Permissions | None:
        cache = self._permissions_cache
        if bearer in cache:
            expiration, permissions_promise = cache[bearer]
            if (
                expiration > now or not permissions_promise.done()
            ):  # not expired
                return await permissions_promise
            del cache[bearer]
        future: Future[Permissions | None] = get_running_loop().create_future()
        # update permissions every 20 seconds
        cache[bearer] = now + 20.0, future
        try:
            permissions = await _api_permissions_for(self._api_client, bearer)
        except BaseException as e:  # just in case
            future.set_exception(e)
            raise
        else:
            future.set_result(permissions)
        return permissions

    async def _bearer_for(
        self, username_password: tuple[str, str], now: float
    ) -> Bearer | None:
        cache = self._bearer_cache
        if username_password in cache:
            expiration, bearer_promise = cache[username_password]
            if expiration > now or not bearer_promise.done():  # not expired
                return await bearer_promise
            del cache[username_password]
        future: Future[Bearer | None] = get_running_loop().create_future()
        cache[username_password] = now + 60.0, future
        try:
            bearer = await _api_bearer_for(
                self._api_client, *username_password
            )
        except BaseException as e:  # just in case
            future.set_exception(e)
            raise
        else:
            future.set_result(bearer)
        return bearer

    async def _check_auth(
        self, request: Request
    ) -> tuple[Permissions | None, Bearer | None]:
        """
        returns:
            * user's Permissions
            * new Bearer that will be stored in a cookie
        """
        now = monotonic()
        if bearer := request.cookies.get("Authorization"):
            # most common way of authorization
            permissions = await self._permissions_for(Bearer(bearer), now)
            # when permissions is None, it means that the Bearer has expired
            if permissions is not None:
                return permissions, None

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            try:
                auth_decoded = b64decode(auth_header[6:]).decode()
                username_password = tuple(auth_decoded.split(":", 1))
                if len(username_password) != 2:
                    return None, None
            except Exception:
                return None, None
            bearer = await self._bearer_for(username_password, now)
            if not bearer:
                return None, None
            return await self._permissions_for(bearer, now), bearer
        elif auth_header.startswith("Bearer "):
            bearer = Bearer(auth_header)
            return await self._permissions_for(bearer, now), None
        return None, None

    async def handle(self, request: Request) -> Response:
        method = request.method
        if method == "OPTIONS":
            return self._response_options

        try:
            permissions, bearer = await self._check_auth(request)
        except NetworkError:
            return self._response_api_failure
        if not permissions:
            return self._response_authentication_required

        dav_path = DAVPath(request.path_params.get("path", "").rstrip("/"))
        if dav_path.startswith("/"):
            # Ideally, frontend should've replaced all '//' with '/'
            return Response("Invalid path", status_code=400)
        full_path = self._path / dav_path
        call = self._methods.get(method)
        if call is not None:
            response = await call(full_path, dav_path, request, permissions)
            if bearer:
                response.set_cookie(
                    "Authorization", bearer, max_age=ONE_MONTH, httponly=True
                )
            return response
        return Response(
            status_code=405, content=f"Method {method} not allowed"
        )

    @aiofiles.base.wrap
    def paths_for(
        self, path: Path, dav_path: DAVPath, permissions: Permissions
    ) -> list[tuple[str, stat_result]] | None:
        """
        :returns: None, when access is denied
        """
        closes_node, children = permissions.list_children(dav_path)
        if closes_node.is_leaf:
            try:
                with scandir(path) as scandir_it:
                    items = {di.name: di.stat() for di in scandir_it}
            except PermissionError:
                return  # disk permissions screwed up
            if children is not None:
                for name in children:
                    if name not in items:
                        child_path = path / name
                        try:
                            stat = child_path.stat()
                        except FileNotFoundError:
                            # user added permission for a directory but didn't
                            # create it beforehand, for convenience crate is here
                            child_path.mkdir()
                            stat = child_path.stat()
                        items[name] = stat
        else:
            if children is None:
                return
            items: dict[str, stat_result] = {}
            for name in children:
                child_path = path / name
                try:
                    stat = child_path.stat()
                except FileNotFoundError:
                    child_path.mkdir()
                    stat = child_path.stat()
                items[name] = stat
        if not dav_path:
            items[PERMISSIONS_NAME] = permissions.stat()

        return list(items.items())

    async def propfind(
        self,
        path: Path,
        dav_path: DAVPath,
        request: Request,
        permissions: Permissions,
    ) -> Response:
        try:
            stat = await aiofiles.os.stat(path)
        except FileNotFoundError:
            if dav_path == PERMISSIONS_NAME:
                stat = permissions.stat()
            elif not permissions.has_read_access(dav_path):
                return Response(**self._kwargs_no_permissions_read)
            else:
                return Response(**self._kwargs_not_found)

        depth = request.headers.get("Depth", "0")
        root = ET.Element("{DAV:}multistatus")

        content_length = request.headers.get("content-length", "0")
        if content_length != "0":
            body = await request.body()
            try:
                ET.fromstring(body)
            except ET.ParseError as e:
                return Response(status_code=400, content=str(e))

        # Add children if depth > 0 and it's a directory
        if depth in ("1", "infinity") and S_ISDIR(stat.st_mode):
            base_url = quote(request.url.path.rstrip("/"))
            try:
                items = await self.paths_for(path, dav_path, permissions)
                if items is None:
                    return Response(**self._kwargs_no_permissions_read)
                self._add_response(
                    root,
                    stat,
                    f"{base_url}/",
                    self._settings.realm if path == self._path else path.name,
                )
                items.sort()
                for name, stat in items:
                    item_url = f"{base_url}/{quote(name)}"
                    if S_ISDIR(stat.st_mode):
                        item_url += "/"
                    self._add_response(root, stat, item_url, name)
            except Exception:
                return Response(**self._kwargs_no_permissions_propfind)
        elif depth in ("0", "1") and permissions.can_traverse(dav_path):
            # Without "1" gvfs refuses to delete file
            self._add_response(
                root,
                stat,
                quote(request.url.path),
                self._settings.realm if path == self._path else path.name,
            )
        else:
            return Response(**self._kwargs_no_permissions_propfind)

        return Response(
            content=ET.tostring(
                root, encoding="unicode", xml_declaration=True
            ),
            media_type='application/xml; charset="utf-8"',
            status_code=207,  # 207 Multi-Status
        )

    def _add_response(
        self,
        parent: ET.Element,
        stat: stat_result,
        url_path: str,
        display_name: str,
    ) -> None:
        """Add a response element for a resource."""
        response = ET.SubElement(parent, "{DAV:}response")
        ET.SubElement(response, "{DAV:}href").text = url_path

        propstat = ET.SubElement(response, "{DAV:}propstat")
        prop = ET.SubElement(propstat, "{DAV:}prop")

        ET.SubElement(prop, "{DAV:}displayname").text = display_name

        # Resource type and other properties
        if S_ISDIR(stat.st_mode):
            resourcetype = ET.SubElement(prop, "{DAV:}resourcetype")
            ET.SubElement(resourcetype, "{DAV:}collection")
            ET.SubElement(prop, "{DAV:}getcontenttype").text = (
                "httpd/unix-directory"
            )
        else:
            ET.SubElement(prop, "{DAV:}resourcetype")
            ET.SubElement(prop, "{DAV:}getcontentlength").text = str(
                stat.st_size
            )
            content_type = _mimetype(display_name, mimetypes_dav)
            ET.SubElement(prop, "{DAV:}getcontenttype").text = content_type

        # Creation date
        ET.SubElement(prop, "{DAV:}creationdate").text = (
            datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        )
        # Last modified
        ET.SubElement(prop, "{DAV:}getlastmodified").text = (
            # st_mtime: last time the file's CONTENTS were changed
            datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime(
                "%a, %d %b %Y %H:%M:%S GMT"
            )
        )
        ET.SubElement(propstat, "{DAV:}status").text = "HTTP/1.1 200 OK"

    async def get(
        self,
        path: Path,
        dav_path: DAVPath,
        request: Request,
        permissions: Permissions,
    ) -> Response:
        try:
            if dav_path == "" and "css" in request.query_params:
                return Response(
                    content=self._css,
                    headers={
                        "Cache-Control": "public, max-age=2592000, immutable",
                    },
                    media_type="text/css",
                )
            stat = await aiofiles.os.stat(path)
        except FileNotFoundError:
            if dav_path == PERMISSIONS_NAME:
                return Response(permissions.txt(), media_type="text/plain")
            if not permissions.has_read_access(dav_path):
                return Response(**self._kwargs_no_permissions_read)
            return Response(**self._kwargs_not_found)

        if S_ISDIR(stat.st_mode):
            item_path = await self.paths_for(path, dav_path, permissions)
            if item_path is None:
                return Response(**self._kwargs_no_permissions_read)
            items: list[str] = []
            if dav_path:
                items.append(
                    '<tr><td><a href="../">../</a></td><td>-</td><td>-</td></tr>'
                )

            ts, utc = datetime.fromtimestamp, timezone.utc
            dirs: Stats = []
            files: Stats = []
            for name_stat in item_path:
                (dirs if S_ISDIR(name_stat[1].st_mode) else files).append(
                    name_stat
                )
            dirs.sort()
            for name, stat in dirs:
                m_time = ts(stat.st_mtime, utc).strftime("%Y-%m-%d %H:%M")
                items.append(
                    f'<tr><td><a href="{quote(name)}/">{name}/</a></td><td>{m_time}</td><td>{_human_readable_size(stat.st_size)}</td></tr>'
                )
            files.sort()
            for name, stat in files:
                href = quote(name)
                m_time = ts(stat.st_mtime, utc).strftime("%Y-%m-%d %H:%M")
                if S_ISREG(stat.st_mode):
                    item = f'<tr><td><a href="{href}">{name}</a></td><td>{m_time}</td><td>{_human_readable_size(stat.st_size)}</td></tr>'
                else:
                    item = f'<tr><td><a style="color:red" href="{href}">{name}</a></td><td>{m_time}</td><td>{_human_readable_size(stat.st_size)}</td></tr>'
                items.append(item)
            root_url = request.url_for("SenyaiDAV", path="")
            title = f"Index of {request.url.path}"
            html = f"""<!DOCTYPE html><html>
<head><title>{title}</title>
<link rel="stylesheet" href="{root_url}?css&{__version__}" type="text/css"></head>
<body><h1>{title}</h1><table>
<thead><tr><th>Name</th><th>Modified</th><th>Size</th></tr></thead>
<tbody>{'\n'.join(items)}</tbody>
</table></body></html>"""
            return Response(html, media_type="text/html")
        elif permissions.has_read_access(dav_path):
            return FileResponse(
                path, media_type=_mimetype(path.name, mimetypes_web)
            )
        else:
            return Response(**self._kwargs_no_permissions_read)

    async def head(
        self,
        path: Path,
        dav_path: DAVPath,
        request: Request,
        permissions: Permissions,
    ) -> Response:
        if not permissions.has_read_access(dav_path):
            return Response(**self._kwargs_no_permissions_read)
        try:
            stat = await aiofiles.os.stat(path)
        except FileNotFoundError:
            return Response(status_code=404)

        if not S_ISDIR(stat.st_mode):
            return Response(
                headers={
                    "Content-Length": str(stat.st_size),
                    "Last-Modified": datetime.fromtimestamp(
                        stat.st_mtime, timezone.utc
                    ).strftime("%a, %d %b %Y %H:%M:%S GMT"),
                    "Content-Type": "application/octet-stream",
                }
            )
        return Response()

    async def put(
        self,
        path: Path,
        dav_path: DAVPath,
        request: Request,
        permissions: Permissions,
    ) -> Response:
        if not permissions.has_write_access(dav_path):
            return Response(**self._kwargs_no_permissions_write)
        await aiofiles.os.makedirs(path.parent, exist_ok=True)

        try:
            async with aiofiles.open(path, "wb") as f:
                async for chunk in request.stream():
                    await f.write(chunk)
            # Total Commander's client sends this `x-last-modified`
            if last_modified_str := request.headers.get("x-last-modified"):
                if (dt := _parse_rfc1123(last_modified_str)) is not None:
                    utime(path, (dt, dt))
            return Response(status_code=201)
        except Exception as e:
            return Response(status_code=500, content=str(e))

    async def delete(
        self,
        path: Path,
        dav_path: DAVPath,
        request: Request,
        permissions: Permissions,
    ) -> Response:
        if not permissions.has_write_access(dav_path):
            return Response(**self._kwargs_no_permissions_write)
        if not path.exists():
            return Response(**self._kwargs_not_found)

        try:
            await delete(path)
            return Response(status_code=204)
        except OSError as e:
            return Response(status_code=409, content=str(e))

    async def mkcol(
        self,
        path: Path,
        dav_path: DAVPath,
        request: Request,
        permissions: Permissions,
    ) -> Response:
        if not permissions.has_write_access(dav_path):
            return Response(**self._kwargs_no_permissions_write)
        content_length = request.headers.get("content-length", "0")
        if content_length != "0":
            if await request.body():
                return Response(
                    content="MKCOL request must not contain a body",
                    status_code=415,  # Unsupported Media Type
                )

        # 2. Check if parent directory exists
        if not path.parent.exists():
            return Response(
                content="Parent collection does not exist",
                status_code=409,  # Conflict
            )

        if path.exists():
            return Response(
                content="Collection already exists",
                status_code=405,  # Method Not Allowed - Correct for existing resource
            )
        try:
            await aiofiles.os.mkdir(path)
            return Response(status_code=201)
        except FileNotFoundError:
            return Response(status_code=409)
        except Exception as e:
            return Response(status_code=500, content=str(e))

    @staticmethod
    def destination(
        request: Request,
    ) -> tuple[DAVPath, str] | tuple[None, None]:
        """
        DAV clients send us "Destination" field in headers in url format
        for example ('http://example.com/dir/p%20x.FCStd`).
        """
        destination = request.headers.get("Destination")
        if destination is not None:
            base_url = request.base_url  # URL('http://example.com/storage/')
            dst_path = unquote(
                URL(destination).path
            )  # '/storage/move destination.txt'
            base_path = base_url.path.rstrip("/")  # example "/storage"
            location = str(base_url.replace(path=quote(base_path + dst_path)))
            return (
                DAVPath(dst_path.removeprefix(base_path).strip("/")),
                location,
            )
        return None, None

    async def copy(
        self,
        source_path: Path,
        dav_path: DAVPath,
        request: Request,
        permissions: Permissions,
    ) -> Response:
        if not permissions.has_read_access(dav_path):
            return Response(**self._kwargs_no_permissions_write)
        destination, location = self.destination(request)
        if not destination:
            return Response(
                status_code=400, content="Destination not specified"
            )
        if not permissions.has_write_access(destination):
            return Response(**self._kwargs_no_permissions_write)
        destination_path = self._path / destination

        if destination_path.exists():
            overwrite = request.headers.get("Overwrite", "T").upper() == "T"
            if overwrite:
                await delete(destination_path)
                # 204 - No Content, Location should be omitted (rfc4918)
                successful_response = Response(status_code=204)
            else:
                return Response(status_code=412)
        else:
            assert location is not None
            successful_response = Response(
                status_code=201, headers={"Location": location}
            )
        try:
            await copy(source_path, destination_path)
        except FileNotFoundError as e:
            return Response(status_code=409, content=str(e))
        except Exception as e:
            # Should not happen, as user only works with files and directories
            return Response(status_code=500, content=str(e))
        return successful_response

    async def move(
        self,
        source_path: Path,
        dav_path: DAVPath,
        request: Request,
        permissions: Permissions,
    ) -> Response:
        if not permissions.has_write_access(dav_path):
            return Response(**self._kwargs_no_permissions_write)
        destination, location = self.destination(request)
        if not destination:
            return Response(
                status_code=400, content="Destination not specified"
            )
        if not permissions.has_write_access(destination):
            return Response(**self._kwargs_no_permissions_write)
        overwrite = request.headers.get("Overwrite", "T").upper() == "T"
        destination_path = self._path / destination
        if destination_path.exists():
            if overwrite:
                await delete(destination_path)
                successful_response = Response(status_code=204)
            else:
                return Response(status_code=412)
        else:
            assert location is not None
            successful_response = Response(
                status_code=201, headers={"Location": location}
            )
        try:
            await aiofiles.os.rename(source_path, destination_path)
        except FileNotFoundError:
            return Response(status_code=404)
        except Exception as e:
            # Should not happen, as user only works with files and directories
            return Response(status_code=500, content=str(e))
        return successful_response

    async def lock(
        self,
        path: Path,
        dav_path: DAVPath,
        request: Request,
        permissions: Permissions,
    ) -> Response:
        """Fake LOCK for Microsoft client"""
        if not permissions.has_write_access(dav_path):
            return Response(**self._kwargs_no_permissions_write)

        lock_scope = "exclusive"  # default
        lock_type = "write"  # default

        if body := await request.body():
            try:
                root = ET.fromstring(body)
            except ET.ParseError as e:
                return Response(status_code=400, content=str(e))
            # Poorly extract lock scope and type
            for elem in root.iter():
                if elem.tag.endswith("lock scope"):
                    lock_scope = elem.text
                elif elem.tag.endswith("lock type"):
                    lock_type = elem.text

        prop = ET.Element("{DAV:}prop")
        lock_discovery = ET.SubElement(prop, "{DAV:}lockdiscovery")
        active_lock = ET.SubElement(lock_discovery, "{DAV:}activelock")

        lock_type_elem = ET.SubElement(active_lock, "{DAV:}locktype")
        if lock_type == "write":
            ET.SubElement(lock_type_elem, "{DAV:}write")

        lock_scope_elem = ET.SubElement(active_lock, "{DAV:}lockscope")
        if lock_scope == "exclusive":
            ET.SubElement(lock_scope_elem, "{DAV:}exclusive")
        else:
            ET.SubElement(lock_scope_elem, "{DAV:}shared")

        depth = request.headers.get("Depth", "0")
        ET.SubElement(active_lock, "{DAV:}depth").text = depth

        owner = ET.SubElement(active_lock, "{DAV:}owner")
        owner_href = ET.SubElement(owner, "{DAV:}href")
        owner_href.text = (
            request.headers.get("Authorization", "unknown").split()[1]
            if "Authorization" in request.headers
            else "anonymous"
        )

        lock_token = ET.SubElement(active_lock, "{DAV:}locktoken")
        lock_token_href = ET.SubElement(lock_token, "{DAV:}href")
        import uuid

        lock_token_href.text = f"opaquelocktoken:{uuid.uuid4()}"

        timeout = request.headers.get("Timeout", "Second-180")
        if timeout.startswith("Second-"):
            timeout_seconds = int(timeout[7:])
        else:
            timeout_seconds = 180  # default
        ET.SubElement(active_lock, "{DAV:}timeout").text = (
            f"Second-{timeout_seconds}"
        )

        return Response(
            content=ET.tostring(
                prop, encoding="unicode", xml_declaration=True
            ),
            media_type='application/xml; charset="utf-8"',
            status_code=200,
            headers={"Lock-Token": f"<{lock_token_href.text}>", "DAV": "1"},
        )

    async def unlock(
        self,
        path: Path,
        dav_path: DAVPath,
        request: Request,
        permissions: Permissions,
    ) -> Response:
        """Fake UNLOCK for Microsoft client"""
        if not permissions.has_write_access(dav_path):
            return Response(**self._kwargs_no_permissions_write)
        lock_token = request.headers.get("Lock-Token", "")
        return Response(status_code=204)

    async def proppatch(
        self,
        path: Path,
        dav_path: DAVPath,
        request: Request,
        permissions: Permissions,
    ) -> Response:
        """Fake PROPPATCH for Microsoft client"""
        if not permissions.has_write_access(dav_path):
            return Response(**self._kwargs_no_permissions_write)
        resource_exists = path.exists()

        root = ET.Element("{DAV:}multistatus")
        response_elem = ET.SubElement(root, "{DAV:}response")
        ET.SubElement(response_elem, "{DAV:}href").text = request.url.path

        propstat = ET.SubElement(response_elem, "{DAV:}propstat")
        prop = ET.SubElement(propstat, "{DAV:}prop")

        if body := await request.body():
            try:
                root_elem = ET.fromstring(body)
            except ET.ParseError as e:
                return Response(status_code=400, content=str(e))
            atime = mtime = None  # access time and modification time
            for prop_update in root_elem.findall(".//{DAV:}set/{DAV:}prop"):
                for child in prop_update:
                    child.tail = None  # remove needless spaces in output
                    prop.append(child)
                    if resource_exists and child.text:
                        # ignoring Win32CreationTime
                        if child.tag.endswith("Win32LastAccessTime"):
                            atime = _parse_rfc1123(child.text)
                        elif child.tag.endswith("Win32LastModifiedTime"):
                            mtime = _parse_rfc1123(child.text)
            if atime is not None and mtime is not None:
                utime(path, (atime, mtime))

        ET.SubElement(propstat, "{DAV:}status").text = "HTTP/1.1 200 OK"

        if not resource_exists:
            user_agent = request.headers.get("User-Agent", "")
            if "Microsoft-WebDAV-MiniRedir" in user_agent:
                pass

        return Response(
            content=ET.tostring(
                root, encoding="unicode", xml_declaration=True
            ),
            media_type='application/xml; charset="utf-8"',
            status_code=207,  # Multi-Status
        )

    async def _run_periodic_tasks(self):
        while True:
            await sleep(60.0)
            now = monotonic()
            for cache in self._bearer_cache, self._permissions_cache:
                keys = [
                    key
                    for key, (expiration, promise) in cache.items()
                    if expiration < now  # expired
                    and promise.done()  # and ready
                ]
                for key in keys:
                    del cache[key]

    @asynccontextmanager
    async def lifespan(self, _starlette: Starlette):
        task = create_task(self._run_periodic_tasks())
        async with AsyncClient(base_url=self._settings.api_url) as api_client:
            self._api_client = api_client
            if self._settings.drop_privileges_user is not None:
                _drop_privileges(self._settings.drop_privileges_user)
            yield
        task.cancel()

    @classmethod
    def create_app(cls, debug: bool = False) -> Starlette:
        dav = cls(_get_settings())
        routes = [Route("/{path:path}", endpoint=dav)]
        return Starlette(routes=routes, debug=debug, lifespan=dav.lifespan)


app = SenyaiDAV.create_app()
