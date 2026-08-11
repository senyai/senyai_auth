from __future__ import annotations

from typing import Any
from unittest import TestCase
from unittest.mock import AsyncMock, patch
from starlette.testclient import TestClient
from httpx2 import AsyncClient, Response, NetworkError
from . import app
from .linkify import linkify


class TestLinkify(TestCase):
    def test_email(self):
        self.assertEqual(
            str(linkify("hello@world.com")),
            '<a href="mailto:hello@world.com"><i class="bi bi-envelope-fill"></i> hello@world.com</a>',
        )

    def test_telephone(self):
        self.assertEqual(
            str(linkify("12345678901")),
            '<a href="tel:12345678901"><i class="bi bi-telephone-fill"></i> 12345678901</a>',
        )

    def test_at(self):
        self.assertEqual(
            str(linkify("@testuser")),
            '<a href="https://t.me/testuser"><i class="bi bi-telegram"></i> @testuser</a>',
        )

    def test_multiple_items_separated_by_newline(self):
        self.assertEqual(
            str(linkify("hello@world.com\n+1(234)5678901\n@testuser")),
            '<a href="mailto:hello@world.com"><i class="bi bi-envelope-fill"></i> hello@world.com</a><br>\n'
            '<a href="tel:+12345678901"><i class="bi bi-telephone-fill"></i> +1(234)5678901</a><br>\n'
            '<a href="https://t.me/testuser"><i class="bi bi-telegram"></i> @testuser</a>',
        )


def JSON(json: Any):
    return Response(status_code=200, json=json)


class FakeWebApi:
    def __new__(cls):
        return patch.multiple(
            AsyncClient,
            get=AsyncMock(side_effect=cls.fake_api_get),
        )

    @classmethod
    def fake_api_get(
        cls, url: str, data: Any = None, headers: Any = None, **kwds: Any
    ) -> Response:
        if url == "/ui/main":
            raise NetworkError("testing network error")
        if url == "/ui/user/1":
            return JSON(
                {
                    "user": {
                        "id": 1,
                        "username": "testuser",
                        "email": "testuser@example.com",
                        "contacts": "+123(456)1234567",
                        "display_name": "Test User",
                    },
                    "inviters": [{"username": "jim", "display_name": "Jim"}],
                },
            )
        if url == "/project/1/add_users":
            return JSON(
                [
                    {
                        "id": i,
                        "username": f"testuser_{i}",
                        "email": f"test{i}@email.com",
                        "display_name": f"Display Name {i}",
                    }
                    for i in range(4, 6)
                ]
            )

        raise ValueError(url)


class WebTest(TestCase):
    maxDiff = 65535

    @classmethod
    def setUpClass(cls) -> None:
        cls._client = TestClient(app).__enter__()
        cls._fake_api = FakeWebApi()
        cls._fake_api.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._client.__exit__()
        cls._fake_api.stop()
        del cls._fake_api, cls._client

    def test_sign_in(self):
        self._client.cookies.clear()
        response = self._client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(">Sign in<", response.text)

    def test_backend_offline(self):
        self._client.cookies["Authorization"] = "xxx"
        response = self._client.get("/")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.text, "")

    def test_user_info_template(self):
        ref_user_info = """<div class="modal-header">
    <h1 class="modal-title fs-5" id="baseModalLabel">User Details</h1>
    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
</div>
<div class="modal-body">
<div class="card">
  <div class="card-body">
    <dl class="row mb-0">
      <dt class="col-12 text-nowrap">Display Name</dt>
      <dd class="col-12">Test User</dd>

      <dt class="col-12 text-nowrap">Username</dt>
      <dd class="col-12">testuser</dd>

      <dt class="col-12 text-nowrap">Email</dt>
      <dd class="col-12">
        <a href="mailto:testuser@example.com">testuser@example.com</a>
      </dd>

      <dt class="col-12 text-nowrap">Contacts</dt>
      <dd class="col-12"><a href="tel:+1234561234567"><i class="bi bi-telephone-fill"></i> +123(456)1234567</a></dd>

      <dt class="col-12 text-nowrap">Invite By</dt>
      <dd class="col-12"><ul>
        <li>Jim (jim)</li>
      </ul></dd>
    </dl>
  </div>
</div>
</div>
<div class="modal-footer">
    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
</div>"""
        self._client.cookies.set("Authorization", "xxx")
        response = self._client.get("/details/1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, ref_user_info)

    def test_add_user_form_template(self):
        ref_add_user_html = """<div class="modal-header">
    <h1 class="modal-title fs-5" id="baseModalLabel">Add Users</h1>
    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
</div>
<div class="modal-body">
<form role="form" class="form-control" id="role-form" hx-post="/project/1/users">
<label class="mb-2">Users</label>
<div class="form-check">
  <label class="form-check-label" title="testuser_4" data-bs-html="true">
    <input type="checkbox" class="form-check-input" name="user" value="4" data-role-checkbox>
    Display Name 4
  </label>
</div>

<div class="form-check">
  <label class="form-check-label" title="testuser_5" data-bs-html="true">
    <input type="checkbox" class="form-check-input" name="user" value="5" data-role-checkbox>
    Display Name 5
  </label>
</div>
</form>
</div>
<div class="modal-footer">
    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
<button type="submit" form="role-form" class="btn btn-primary">Add Users</button>
</div>"""
        self._client.cookies.set("Authorization", "xxx")
        response = self._client.get("/project/1/users")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, ref_add_user_html)
