from __future__ import annotations
from typing import Any
from unittest import TestCase, IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch
from starlette.testclient import TestClient
from . import Permissions, DAVPath, SenyaiDAV, DavSettings, PERMISSIONS_NAME
from senyai_auth import server_dav, __version__ as version
import httpx2 as httpx
from httpx2 import AsyncClient
from pathlib import Path
import tempfile
from datetime import datetime, timezone


class PermissionsTest(TestCase):
    def test_user_can_only_see_their_folder(self) -> None:
        perm = Permissions(["user1"])
        _node, folders = perm.list_children(DAVPath(""))
        self.assertEqual(folders, ["user1"])

    def test_user_have_no_access_to_outside_directory(self) -> None:
        perm = Permissions(["user1"])
        node, folders = perm.list_children(DAVPath("xx"))
        self.assertIsNone(folders)
        self.assertIs(node, getattr(perm, "_root"))

    def test_duplicate_permissions(self) -> None:
        perm = Permissions(
            ["user1", "user1", "user2", "user2:w", "user1:w", "user3", "user3"]
        )
        node, folders = perm.list_children(DAVPath(""))
        self.assertIs(node, getattr(perm, "_root"))
        self.assertEqual(folders, ["user1", "user2", "user3"])
        self.assertTrue(perm.has_read_access(DAVPath("user1")))
        self.assertTrue(perm.has_write_access(DAVPath("user1")))
        self.assertTrue(perm.has_read_access(DAVPath("user2")))
        self.assertTrue(perm.has_write_access(DAVPath("user2")))
        self.assertTrue(perm.has_read_access(DAVPath("user3")))
        self.assertFalse(perm.has_write_access(DAVPath("user3")))


def _test_settings(path: str):
    print(f"using path {path} for testing")
    return lambda: DavSettings(path=path)


class DavAppUnauthorizedTest(IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with patch.object(
            server_dav,
            "_get_settings",
            new=_test_settings(tempfile.gettempdir()),
        ):
            cls._app = SenyaiDAV.create_app()
        cls._client = TestClient(cls._app).__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._client.__exit__()

    def test_get_root(self) -> None:
        response = self._client.get("/")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.content, b"Authentication required")
        self.assertEqual(
            response.headers,
            {
                "www-authenticate": 'Basic realm="Storage"',
                "content-length": "23",
            },
        )

    def test_options(self) -> None:
        response = self._client.options("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"")
        self.assertEqual(
            response.headers,
            {
                "dav": "1",
                "allow": "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, LOCK, UNLOCK, PROPPATCH",
                "content-length": "0",
            },
        )

    def test_authentication_is_required_for_unsupported_method(self) -> None:
        response = self._client.request("CRACK", "/")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.content, b"Authentication required")


AUTH = {"Authorization": "Basic dXNlcm5hbWU6cGFzc3dvcmQ="}
AUTH_RO_D = {"Authorization": "Basic cm86cjFiMQ=="}


class FakeApi:
    USERS = {
        "username": {
            "password": "password",
            "permissions": ["/:r", "/d:w"],
            "token": {"token_type": "my_type", "access_token": "my_access"},
        },
        "ro": {
            "password": "r1b1",
            "permissions": ["d:r"],
            "token": {"token_type": "my_type", "access_token": "yyy"},
        },
    }

    def __new__(cls):
        return patch.multiple(
            AsyncClient,
            post=AsyncMock(side_effect=cls.fake_api_post),
            get=AsyncMock(side_effect=cls.fake_api_get),
        )

    @classmethod
    def fake_api_post(cls, url: Any, data: Any, **kwds: Any) -> httpx.Response:
        user = cls.USERS.get(data["username"])
        if user is None or user["password"] != data["password"]:
            return httpx.Response(status_code=401)
        if url == "/token":
            return httpx.Response(
                json=user["token"],
                status_code=200,
                headers={"Content-Type": "text/json"},
            )
        raise ValueError(url)

    @classmethod
    def fake_api_get(
        cls, url: Any, data: Any = None, headers: Any = None, **kwds: Any
    ) -> httpx.Response:
        if data is not None:
            user = cls.USERS.get(data["username"])
            if user is None or user["password"] != data["password"]:
                return httpx.Response(status_code=401)
        elif headers is not None:
            tp, access = headers["Authorization"].split()
            token = {"token_type": tp.lower(), "access_token": access}
            query = (
                user for user in cls.USERS.values() if user["token"] == token
            )
            user = next(query, None)
            if user is None:
                return httpx.Response(status_code=401)
        else:
            assert False
        if url == "/ldap/roles/storage":
            return httpx.Response(
                json=user["permissions"],
                status_code=200,
                headers={"Content-Type": "text/json"},
            )
        raise ValueError(url)


class DavAppTest(IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Setup test directory
        cls._temp_dir = tempfile.TemporaryDirectory()
        cls._path = Path(cls._temp_dir.name)
        for idx, name in enumerate([*"abc", "ёлки иголки.png"]):
            (cls._path / name).write_text(name * idx * 3)

        # Path settings and create `app``
        with patch.object(
            server_dav,
            "_get_settings",
            new=_test_settings(cls._temp_dir.name),
        ):
            cls._app = SenyaiDAV.create_app()

        # Start test client for the dav
        cls._client = TestClient(cls._app).__enter__()

        # Patch API
        cls._fake_api = FakeApi()
        cls._fake_api.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temp_dir.cleanup()
        cls._client.__exit__()
        cls._fake_api.stop()

    def tearDown(self) -> None:
        self._client.cookies.clear()

    def test_get_no_permissions(self) -> None:
        # we have no permissions, because we don't sent Authorization
        response = self._client.get("")
        self.assertEqual(response.status_code, 401)
        response = self._client.get("/xxx")
        self.assertEqual(response.status_code, 401)

    def test_get_root_directory(self) -> None:
        response = self._client.get("/", headers=AUTH)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.content,
            f"""<html>
<head><title>Index of /</title></head>
<body>
<h1>Index of /</h1>
<ul>
<li><a href="a">a</a></li>
<li><a href="b">b</a></li>
<li><a href="c">c</a></li>
<li><a href="d/">d/</a></li>
<li><a style="color:red" href="{PERMISSIONS_NAME}">{PERMISSIONS_NAME}</a></li>
<li><a href="%D1%91%D0%BB%D0%BA%D0%B8%20%D0%B8%D0%B3%D0%BE%D0%BB%D0%BA%D0%B8.png">ёлки иголки.png</a></li>
</ul>
<hr><small>Powered by senyai_auth {version}</small>
</body>
</html>""".encode(),
        )

    def test_get_file(self) -> None:
        response = self._client.get("/b", headers=AUTH)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"b" * 3)

    @staticmethod
    def _file_stat(path: Path) -> tuple[str, str]:
        if path.name == PERMISSIONS_NAME:
            return "1970-01-01T00:00:00Z", "Thu, 01 Jan 1970 00:00:00 GMT"
        stat = path.stat()
        getlastmodified = datetime.fromtimestamp(
            stat.st_mtime, timezone.utc
        ).strftime("%a, %d %b %Y %H:%M:%S GMT")
        creationdate = datetime.fromtimestamp(
            stat.st_ctime, timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        return creationdate, getlastmodified

    @classmethod
    def _pf_response(
        cls,
        path: Path,
        displayname: str,
        href: str,
        contenttype: str,
        length: int | None = None,
    ) -> str:
        creationdate, getlastmodified = cls._file_stat(path)
        if contenttype == "httpd/unix-directory":
            resourcetype = "<D:resourcetype><D:collection /></D:resourcetype>"
            getcontentlength = ""
        else:
            resourcetype = "<D:resourcetype />"
            getcontentlength = (
                f"<D:getcontentlength>{length}</D:getcontentlength>"
            )
        return (
            # fmt: off
            f'<D:response><D:href>{href}</D:href>'
              '<D:propstat>'
                '<D:prop>'
                  f'<D:displayname>{displayname}</D:displayname>'
                  f"{resourcetype}"
                  f"{getcontentlength}"
                  f'<D:getcontenttype>{contenttype}</D:getcontenttype>'
                  f'<D:creationdate>{creationdate}</D:creationdate>'
                  f'<D:getlastmodified>{getlastmodified}</D:getlastmodified>'
                '</D:prop>'
                '<D:status>HTTP/1.1 200 OK</D:status>'
              '</D:propstat>'
            '</D:response>'
            # fmt: on
        )

    @classmethod
    def _multistatus(cls, *responses: str) -> bytes:
        return "".join(
            [
                "<?xml version='1.0' encoding='utf-8'?>\n"
                '<D:multistatus xmlns:D="DAV:">',
                *responses,
                "</D:multistatus>",
            ]
        ).encode()

    def test_propfind_on_root_directory_with_default_depth_0(self) -> None:
        response = self._client.request("PROPFIND", "/", headers=AUTH)
        self.assertEqual(response.status_code, 207)
        self.assertEqual(
            response.content,
            self._multistatus(
                self._pf_response(
                    self._path, "Storage", "/", "httpd/unix-directory"
                )
            ),
        )

    def test_propfind_on_root_directory_with_depth_1(self) -> None:
        response = self._client.request(
            "PROPFIND", "/", headers={**AUTH, "Depth": "1"}
        )
        self.assertEqual(response.status_code, 207)
        ref_content = self._multistatus(
            self._pf_response(
                self._path, "Storage", "/", "httpd/unix-directory"
            ),
            self._pf_response(
                self._path / "a", "a", "/a", "application/octet-stream", 0
            ),
            self._pf_response(
                self._path / "b", "b", "/b", "application/octet-stream", 3
            ),
            self._pf_response(
                self._path / "c", "c", "/c", "application/octet-stream", 6
            ),
            self._pf_response(
                self._path / "d", "d", "/d/", "httpd/unix-directory"
            ),
            self._pf_response(
                self._path / PERMISSIONS_NAME,
                PERMISSIONS_NAME,
                f"/{PERMISSIONS_NAME}",
                "text/plain",
                12,
            ),
            self._pf_response(
                self._path / "ёлки иголки.png",
                "ёлки иголки.png",
                "/%D1%91%D0%BB%D0%BA%D0%B8%20%D0%B8%D0%B3%D0%BE%D0%BB%D0%BA%D0%B8.png",
                "image/png",
                225,
            ),
        )
        self.assertEqual(response.content, ref_content)

    def test_propfind_on_root_directory_with_depth_1_strict(self) -> None:
        response = self._client.request(
            "PROPFIND", "/", headers={**AUTH_RO_D, "Depth": "1"}
        )
        self.assertEqual(response.status_code, 207)
        ref_content = self._multistatus(
            self._pf_response(
                self._path, "Storage", "/", "httpd/unix-directory"
            ),
            self._pf_response(
                self._path / "d", "d", "/d/", "httpd/unix-directory"
            ),
            self._pf_response(
                self._path / PERMISSIONS_NAME,
                PERMISSIONS_NAME,
                f"/{PERMISSIONS_NAME}",
                "text/plain",
                5,
            ),
        )
        self.assertEqual(response.content, ref_content)

    def test_propfind_on_root_directory_with_permissions(self) -> None:
        response = self._client.request(
            "PROPFIND", "/d", headers={**AUTH, "Depth": "1"}
        )
        self.assertEqual(response.status_code, 207)
        d_path = self._path / "d"
        ref_content = self._multistatus(
            self._pf_response(d_path, "d", "/d/", "httpd/unix-directory"),
            self._pf_response(
                d_path / "new", "new", "/d/new/", "httpd/unix-directory"
            ),
        )
        self.assertEqual(response.content, ref_content)

    def test_propfind_on_a_file(self) -> None:
        response = self._client.request(
            "PROPFIND", "/ёлки иголки.png", headers=AUTH
        )
        self.assertEqual(response.status_code, 207)
        creationdate, getlastmodified = self._file_stat(
            self._path / "ёлки иголки.png"
        )
        self.assertEqual(
            response.content,
            # fmt: off
            ("<?xml version='1.0' encoding='utf-8'?>\n"
             '<D:multistatus xmlns:D="DAV:">'
               '<D:response><D:href>/%D1%91%D0%BB%D0%BA%D0%B8%20%D0%B8%D0%B3%D0%BE%D0%BB%D0%BA%D0%B8.png</D:href>'
                 '<D:propstat>'
                   '<D:prop>'
                     '<D:displayname>ёлки иголки.png</D:displayname>'
                     '<D:resourcetype />'
                     '<D:getcontentlength>225</D:getcontentlength>'
                     '<D:getcontenttype>image/png</D:getcontenttype>'
                     f'<D:creationdate>{creationdate}</D:creationdate>'
                     f'<D:getlastmodified>{getlastmodified}</D:getlastmodified>'
                   '</D:prop>'
                   '<D:status>HTTP/1.1 200 OK</D:status>'
                 '</D:propstat>'
               '</D:response>'
             '</D:multistatus>').encode(),
            # fmt: on
        )

    def test_propfind_on_non_existing_file(self) -> None:
        response = self._client.request(
            "PROPFIND", "/non_existing_file", headers=AUTH
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b"404 Not Found")

    def test_delete_on_non_existing_file(self) -> None:
        response = self._client.delete("/d/non_existing_file", headers=AUTH)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b"404 Not Found")

    def test_mkcol_non_existing_directory(self) -> None:
        response = self._client.request("MKCOL", "/d/new", headers=AUTH)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.content, b"")

    def test_mkcol_non_existing_directory_again(self) -> None:
        response = self._client.request("MKCOL", "/d", headers=AUTH)
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.content, b"Collection already exists")

    def test_mkcol_parent_collection_does_not_exist(self) -> None:
        response = self._client.request("MKCOL", "/d/a/b/c", headers=AUTH)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.content, b"Parent collection does not exist")

    def test_mkcol_with_body(self) -> None:
        response = self._client.request(
            "MKCOL", "/d/test_failed", content="body", headers=AUTH
        )
        self.assertEqual(response.status_code, 415)
        self.assertEqual(
            response.content, b"MKCOL request must not contain a body"
        )

    def test_mkcol_without_write_permission(self) -> None:
        response = self._client.request("MKCOL", "/l", headers=AUTH)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content, b"Write permission denied")

    def test_unsupported_method(self) -> None:
        response = self._client.request("CRACK", "/", headers=AUTH)
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.content, b"Method CRACK not allowed")

    def test_propfind_with_invalid_xml(self) -> None:
        response = self._client.request(
            "PROPFIND", "/", content="<hello>", headers=AUTH
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.content, b"no element found: line 1, column 7"
        )

    def test_head_for_valid_file(self) -> None:
        response = self._client.head("/a", headers=AUTH)
        getlastmodified = (
            datetime.fromtimestamp(
                (self._path / "a").stat().st_mtime, timezone.utc
            )
            .strftime("%a, %d %b %Y %H:%M:%S GMT")
            .encode()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.raw,
            [
                (b"content-length", b"0"),
                (b"last-modified", getlastmodified),
                (b"content-type", b"application/octet-stream"),
                (
                    b"set-cookie",
                    b'Authorization="My_type my_access"; '
                    b"Max-Age=2592000; Path=/; SameSite=lax",
                ),
            ],
        )
        self.assertEqual(response.content, b"")

    def test_head_for_valid_directory(self) -> None:
        response = self._client.head("/", headers=AUTH)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers,
            {
                "content-length": "0",
                "set-cookie": 'Authorization="My_type my_access"; Max-Age=2592000; Path=/; '
                "SameSite=lax",
            },
        )
        self.assertEqual(response.content, b"")

    def test_head_for_non_existing_path(self) -> None:
        response = self._client.head("/non_existing_file", headers=AUTH)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b"")

    def test_delete_existing_file(self) -> None:
        CONTENT = b"A file to be deleted by test"
        response = self._client.put(
            "/d/deleteme", headers=AUTH, content=CONTENT
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.content, b"")

        response = self._client.get("/d/deleteme", headers=AUTH)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, CONTENT)

        response = self._client.delete("/d", headers=AUTH)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.content, b"")

        response = self._client.get("/d/deleteme", headers=AUTH)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b"404 Not Found")

    def test_delete_non_existing_file(self) -> None:
        response = self._client.delete("/d/non_existing_file", headers=AUTH)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b"404 Not Found")

    def test_delete_file_without_having_write_permission(self) -> None:
        response = self._client.delete("/a", headers=AUTH)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content, b"Write permission denied")

    def test_put_without_write_permission(self) -> None:
        response = self._client.put("/x", headers=AUTH, content=b"X")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content, b"Write permission denied")

    def test_copy_without_destination(self) -> None:
        response = self._client.request("COPY", "/x", headers=AUTH)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b"Destination not specified")

    def test_move_without_destination(self) -> None:
        response = self._client.request("MOVE", "/d", headers=AUTH)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b"Destination not specified")

    def test_move_non_existing_file(self) -> None:
        response = self._client.request(
            "MOVE",
            "/d/non_existing_file",
            headers={**AUTH, "Destination": "/d/file_dst"},
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b"")

    def test_rename(self) -> None:
        pass

    def test_move_basic(self) -> None:
        CONTENT = b"A file to be moved by test"
        response = self._client.put(
            "/d/move_me", headers=AUTH, content=CONTENT
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.content, b"")

        response = self._client.request(
            "MOVE",
            "/d/move_me",
            headers={
                **AUTH,
                "Destination": "http://example.com/d/move%20destination.txt",
            },
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.content, b"")
        self.assertEqual(
            response.headers.raw,
            [
                (
                    b"location",
                    b"http://testserver/d/move%20destination.txt",
                ),
                (b"content-length", b"0"),
            ],
        )

        response = self._client.get("/d/move%20destination.txt")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, CONTENT)

        response = self._client.get("/d/move_me")
        self.assertEqual(response.status_code, 404)

        response = self._client.delete(
            "/d/move%20destination.txt", headers=AUTH
        )
        self.assertEqual(response.status_code, 204)

    def test_copy_basic(self) -> None:
        CONTENT = b"A file to be copied by test"
        response = self._client.put(
            "/d/copy_me", headers=AUTH, content=CONTENT
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.content, b"")

        response = self._client.request(
            "COPY",
            "/d/copy_me",
            headers={
                **AUTH,
                "Destination": "http://example.com/d/copy%20destination.txt",
            },
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.content, b"")
        self.assertEqual(
            response.headers.raw,
            [
                (
                    b"location",
                    b"http://testserver/d/copy%20destination.txt",
                ),
                (b"content-length", b"0"),
            ],
        )

        response = self._client.get("/d/copy%20destination.txt")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, CONTENT)

        response = self._client.get("/d/copy_me")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, CONTENT)

    def test_get_permissions_txt(self):
        response = self._client.get("/permissions.txt", headers=AUTH)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"* /:r\n* /d:w")

    def test_get_permissions_txt_strict(self):
        response = self._client.get("/permissions.txt", headers=AUTH_RO_D)
        self.assertEqual(response.status_code, 200)
        # self.assertEqual(response.content, b"* /:r\n* /d:w")
