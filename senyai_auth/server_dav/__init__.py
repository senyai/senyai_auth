# import os
from __future__ import annotations
from typing import NamedTuple, NewType
from os import stat_result, getenv
from stat import S_ISDIR
from base64 import b64decode
from collections import defaultdict
from collections.abc import Callable, Awaitable
import xml.etree.ElementTree as ET
from datetime import datetime
from starlette.applications import Starlette
from starlette.responses import Response, FileResponse
from starlette.requests import Request
from starlette.routing import Route
from starlette.types import Scope, Receive, Send
from starlette.datastructures import URL
import aiofiles
import aiofiles.os
from pathlib import Path
from mimetypes import types_map as mimetypes
from httpx import AsyncClient, NetworkError
from contextlib import asynccontextmanager
from time import monotonic
from asyncio import Future, create_task, sleep
import httpcore  # needed for _drop_privileges
import anyio._backends._asyncio  # needed for _drop_privileges
from .afs import copy, delete


class DavSettings(NamedTuple):
    path: str = "."
    realm: str = "Storage"
    api_url: str = "http://127.0.0.1:8000"
    drop_privileges_user: str | None = None


# path with slash at the beginning and at the end
DAVPath = NewType("DAVPath", str)
# non empty authorization string that goes directly into api backend
Authorization = NewType("Authorization", str)

ONE_MONTH = 30 * 24 * 60 * 60


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


class Permissions:
    def __init__(self, paths: list[str]) -> None:
        self._root = root = Node()
        for path_rw in paths:
            node = root
            path, _, rights = path_rw.rpartition(":")
            path = path.strip("/")
            if path:  # without this check root can't become leaf
                for item in path.split("/"):
                    node = node.children[item]
            node.can_write |= rights == "w"
            node.is_leaf = True

    def closet_node(self, path: DAVPath) -> Node:
        node = self._root
        for item in path.split("/"):
            if item in node.children:
                node = node.children[item]
            else:
                return node
        return node

    def has_write_access(self, path: DAVPath) -> bool:
        node = self.closet_node(path)
        return node.is_leaf and node.can_write

    def has_read_access(self, path: DAVPath) -> bool:
        return self.closet_node(path).is_leaf

    def can_traverse(self, path: DAVPath) -> bool:
        return (
            not path
            or self.closet_node(path) is not self._root
            or self._root.is_leaf
        )

    def list_children(self, path: DAVPath) -> list[str] | None:
        """
        List nodes
        """
        node = self._root
        if path:
            for item in path.split("/"):
                if item in node.children:
                    node = node.children[item]
                else:
                    return None
        return list(node.children)


def _drop_privileges(username: str) -> None:
    import pwd, os

    pw = pwd.getpwnam(username)
    target_uid = pw.pw_uid
    target_gid = pw.pw_gid
    os.setgroups([])
    os.setgid(target_gid)
    os.setuid(target_uid)


async def _authorization_for(
    api_client: AsyncClient,
    username: str,
    password: str,
) -> Authorization | None:
    token_res = await api_client.post(
        "/token",
        data={"username": username, "password": password},
    )
    if token_res.status_code != 200:  # login and password are invalid.
        return None

    token = token_res.json()
    return Authorization(
        f"{token['token_type'].capitalize()} {token['access_token']}"
    )


async def _permissions_for(
    api_client: AsyncClient, authorization_str: Authorization
) -> Permissions | None:
    permissions_res = await api_client.get(
        "/ldap/roles/storage", headers={"Authorization": authorization_str}
    )
    if permissions_res.status_code != 200:
        return None
    return Permissions(permissions_res.json())


class SenyaiDAV:
    def __init__(self, settings: DavSettings) -> None:
        self._settings = settings
        self._path = Path(settings.path)

        self._methods: dict[
            str,
            Callable[
                [Path, DAVPath, Request, Permissions], Awaitable[Response]
            ],
        ] = {
            "OPTIONS": self.options,
            "PROPFIND": self.propfind,
            "GET": self.get,
            "HEAD": self.head,
            "PUT": self.put,
            "DELETE": self.delete,
            "MKCOL": self.mkcol,
            "COPY": self.copy,
            "MOVE": self.move,
        }
        self._response_options = Response(
            headers={
                "DAV": "1",
                "Allow": ", ".join(self._methods),
                "Content-Length": "0",
            }
        )
        self._response_authentication_required = Response(
            content="Authentication required",
            status_code=401,
            # Info: we can only use Basic Authentication, because
            #       it is the one that shows username/password dialog
            headers={"WWW-Authenticate": f'Basic realm="{settings.realm}"'},
        )
        self._response_no_permissions_write = Response(
            content="Write permission denied",
            status_code=403,
            headers={"Content-Type": "text/plain", "DAV": "1"},
        )
        error = ET.Element("{DAV:}error")
        ET.SubElement(error, "{DAV:}privilege")
        ET.SubElement(error, "{DAV:}read")
        self._response_no_permissions_propfind = Response(
            content=ET.tostring(error, encoding="unicode"),
            media_type='application/xml; charset="utf-8"',
            status_code=403,
        )
        self._response_no_permissions_read = Response(
            content="403 Read permission denied", status_code=403
        )
        self._response_not_found = Response(
            content="404 Not Found", status_code=404
        )
        self._response_api_failure = Response(
            content="Authentication backend is down", status_code=503
        )
        self._auth_cache: dict[
            tuple[str, str], tuple[float, Future[Authorization | None]]
        ] = {}
        self._permissions_cache: dict[
            Authorization, tuple[float, Future[Permissions | None]]
        ] = {}

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":  # websocket or something
            return
        response = await self.handle(Request(scope, receive))
        await response(scope, receive, send)

    async def _permissions_for(
        self, authorization: Authorization, now: float
    ) -> Permissions | None:
        cache = self._permissions_cache
        if authorization in cache:
            expiration, permissions = cache[authorization]
            if expiration > now:  # not expired
                return await permissions
            del cache[authorization]
        future: Future[Permissions | None] = Future()
        # update permissions every 20 seconds
        cache[authorization] = now + 20.0, future
        permissions = await _permissions_for(self._api_client, authorization)
        future.set_result(permissions)
        return permissions

    async def _authorization_for(
        self, username_password: tuple[str, str], now: float
    ) -> Authorization | None:
        cache = self._auth_cache
        if username_password in cache:
            expiration, authorization = cache[username_password]
            if expiration > now:  # not expired
                return await authorization
            del cache[username_password]
        future: Future[Authorization | None] = Future()
        cache[username_password] = now + 60.0, future
        authorization = await _authorization_for(
            self._api_client, *username_password
        )
        future.set_result(authorization)
        return authorization

    async def _check_auth(
        self, request: Request
    ) -> tuple[Permissions | None, Authorization | None]:
        now = monotonic()
        authorization_str = request.cookies.get("Authorization")
        if authorization_str:
            return (
                await self._permissions_for(
                    Authorization(authorization_str), now
                )
            ), None

        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Basic "):
            return None, None

        try:
            auth_decoded = b64decode(auth_header[6:]).decode()
            username_password = tuple(auth_decoded.split(":", 1))
            if len(username_password) != 2:
                return None, None
        except Exception:
            return None, None

        authorization = await self._authorization_for(username_password, now)
        if not authorization:
            return None, None
        return await self._permissions_for(authorization, now), authorization

    async def handle(self, request: Request) -> Response:
        method = request.method

        if method == "OPTIONS":
            return await self.options(None, None, None, None)

        try:
            permissions, authorization = await self._check_auth(request)
        except NetworkError:
            return self._response_api_failure
        if not permissions:
            return self._response_authentication_required

        dav_path = DAVPath(request.path_params.get("path", "").rstrip("/"))
        assert not dav_path.startswith("/")
        full_path = self._path / dav_path
        call = self._methods.get(method)
        if call is not None:
            response = await call(full_path, dav_path, request, permissions)
            if authorization:
                response.set_cookie(
                    "Authorization", authorization, max_age=ONE_MONTH
                )
            return response
        return Response(
            status_code=405, content=f"Method {method} not allowed"
        )

    async def options(
        self,
        path: Path | None,
        dav_path: DAVPath | None,
        request: Request | None,
        permissions: Permissions | None,
    ) -> Response:
        return self._response_options

    def paths_for(
        self, path: Path, dav_path: DAVPath, permissions: Permissions
    ) -> list[Path] | None:
        if permissions.has_read_access(dav_path):
            items = list(path.iterdir())
        else:
            children = permissions.list_children(dav_path)
            if children is None:
                return
            items = [self._path / dav_path / child for child in children]
        items.sort()
        return items

    async def propfind(
        self,
        path: Path,
        dav_path: DAVPath,
        request: Request,
        permissions: Permissions,
    ) -> Response:
        if not path.exists():
            if not permissions.has_read_access(dav_path):
                return self._response_no_permissions_read
            return self._response_not_found

        depth = request.headers.get("Depth", "0")
        root = ET.Element("{DAV:}multistatus")

        content_length = request.headers.get("content-length", "0")
        if content_length != "0":
            body = await request.body()
            try:
                ET.fromstring(body)
            except Exception as e:
                return Response(status_code=400, content=str(e))

        # Add children if depth > 0 and it's a directory
        if depth in ("1", "infinity") and path.is_dir():
            base_url = request.url.path.rstrip("/")
            try:
                items = self.paths_for(path, dav_path, permissions)
                if items is None:
                    return self._response_no_permissions_read
                self._add_response(root, path.stat(), request.url.path, path)

                for item_path in items:
                    item_url = f"{base_url}/{item_path.name}"
                    stat = item_path.stat()
                    if S_ISDIR(stat.st_mode):
                        item_url += "/"

                    self._add_response(root, stat, item_url, item_path)
            except Exception:
                return self._response_no_permissions_propfind
        elif depth == "0" and permissions.can_traverse(dav_path):
            self._add_response(root, path.stat(), request.url.path, path)
        else:
            return self._response_no_permissions_propfind

        return Response(
            content=ET.tostring(root, encoding="unicode"),
            media_type='application/xml; charset="utf-8"',
            status_code=207,  # 207 Multi-Status
        )

    def _add_response(
        self,
        parent: ET.Element,
        stat: stat_result,
        url_path: str,
        fs_path: Path,
    ) -> None:
        """Add a response element for a resource."""
        response = ET.SubElement(parent, "{DAV:}response")
        ET.SubElement(response, "{DAV:}href").text = url_path

        propstat = ET.SubElement(response, "{DAV:}propstat")
        prop = ET.SubElement(propstat, "{DAV:}prop")

        # Display name
        display_name = fs_path.name
        if not display_name:  # Root
            display_name = "/"
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
            ext = fs_path.suffix.lower()
            content_type = mimetypes.get(ext, "application/octet-stream")
            ET.SubElement(prop, "{DAV:}getcontenttype").text = content_type

        # Last modified
        last_modified = datetime.fromtimestamp(stat.st_mtime).strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        ET.SubElement(prop, "{DAV:}getlastmodified").text = last_modified
        ET.SubElement(propstat, "{DAV:}status").text = "HTTP/1.1 200 OK"

    async def get(
        self,
        path: Path,
        dav_path: DAVPath,
        request: Request,
        permissions: Permissions,
    ) -> Response:
        if not path.exists():
            if not permissions.has_read_access(dav_path):
                return self._response_no_permissions_read
            return self._response_not_found

        if path.is_dir():
            item_path = self.paths_for(path, dav_path, permissions)
            if item_path is None:
                return self._response_no_permissions_read
            # Simple directory listing
            items: list[str] = []
            if dav_path:
                items.append('<li><a href="../">../</a></li>')
            base_url = request.url.path.rstrip("/")

            for item_path in item_path:
                name = item_path.name
                url = f"{base_url}/{name}"
                if item_path.is_dir():
                    item = f'<li><a href="{url}/">{name}/</a></li>'
                else:
                    item = f'<li><a href="{url}">{name}</a></li>'
                items.append(item)

            html = f"""<html>
<head><title>Index of {request.url.path}</title></head>
<body>
<h1>Index of {request.url.path}</h1>
<ul>
{'\n'.join(items)}
</ul>
</body>
</html>"""
            return Response(html, media_type="text/html")
        elif permissions.has_read_access(dav_path):
            return FileResponse(path)
        else:
            return self._response_no_permissions_read

    async def head(
        self,
        path: Path,
        dav_path: DAVPath,
        request: Request,
        permissions: Permissions,
    ) -> Response:
        if not permissions.has_read_access(dav_path):
            return self._response_no_permissions_read
        try:
            stat = await aiofiles.os.stat(path)
        except FileNotFoundError:
            return Response(status_code=404)

        if not S_ISDIR(stat.st_mode):
            return Response(
                headers={
                    "Content-Length": str(stat.st_size),
                    "Last-Modified": datetime.fromtimestamp(
                        stat.st_mtime
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
            return self._response_no_permissions_write
        path.parent.mkdir(exist_ok=True, parents=True)

        try:
            async with aiofiles.open(path, "wb") as f:
                async for chunk in request.stream():
                    await f.write(chunk)
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
            return self._response_no_permissions_write
        if not path.exists():
            return Response(status_code=404)

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
            return self._response_no_permissions_write
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
    def destination(request: Request) -> DAVPath | None:
        destination = request.headers.get("Destination")
        if destination is not None:
            return DAVPath(URL(destination).path.strip("/"))

    async def copy(
        self,
        source_path: Path,
        dav_path: DAVPath,
        request: Request,
        permissions: Permissions,
    ) -> Response:
        if not permissions.has_read_access(dav_path):
            return self._response_no_permissions_write
        destination = self.destination(request)
        if not destination:
            return Response(
                status_code=400, content="Destination not specified"
            )
        if not permissions.has_write_access(DAVPath(destination)):
            return self._response_no_permissions_write
        destination_path = self._path / destination
        successful_response = Response(
            status_code=201, headers={"Location": destination}
        )

        if destination_path.exists():
            overwrite = request.headers.get("Overwrite", "T").upper() == "T"
            if overwrite:
                await delete(destination_path)
                successful_response.status_code = 204
            else:
                return Response(status_code=412)
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
            return self._response_no_permissions_write
        destination = self.destination(request)
        if not destination:
            return Response(
                status_code=400, content="Destination not specified"
            )
        if not permissions.has_write_access(destination):
            return self._response_no_permissions_write
        overwrite = request.headers.get("Overwrite", "T").upper() == "T"
        destination_path = self._path / destination
        successful_response = Response(
            status_code=201, headers={"Location": destination}
        )
        if destination_path.exists():
            if overwrite:
                await delete(destination_path)
                successful_response.status_code = 204
            else:
                return Response(status_code=412)
        try:
            await aiofiles.os.rename(source_path, destination_path)
        except Exception as e:
            # Should not happen, as user only works with files and directories
            return Response(status_code=500, content=str(e))
        return successful_response

    async def _run_periodic_tasks(self):
        while True:
            await sleep(60.0)
            now = monotonic()
            for cache in self._auth_cache, self._permissions_cache:
                keys = [
                    key
                    for key, (expiration, _) in cache.items()
                    if expiration < now  # expired
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
