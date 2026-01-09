from __future__ import annotations
from fastapi.testclient import TestClient
from unittest import TestCase, IsolatedAsyncioTestCase
from sqlalchemy.exc import IntegrityError

from . import app, get_settings, AppSettings
from .db import Project, Role, User


def test_get_settings():
    return AppSettings(
        db_url="sqlite+aiosqlite:///:memory:", secret_key="debug" * 6
    )


app.dependency_overrides[get_settings] = test_get_settings
client = TestClient(app)
client.__enter__()


class UnauthorizedTest(TestCase):
    def test_all(self):
        for path, method in (
            ("/whoami", "get"),
            ("/", "get"),
            ("/user", "post"),
            ("/users", "get"),
            ("/project", "post"),
            ("/project/1", "patch"),
            ("/projects", "get"),
        ):
            response = client.request(method, path)
            self.assertEqual(
                response.status_code, 401, msg=f"{path} must check user"
            )


class TokenFailureTest(TestCase):
    def test_invalid_method(self):
        response = client.get("/token")
        self.assertEqual(response.status_code, 405)

    def test_unprocessable_content(self):
        response = client.post("/token")
        self.assertEqual(response.status_code, 422)

    def test_unauthorized(self):
        response = client.post(
            "/token",
            data={
                "username": "xxx",
                "password": "yyy",
            },
        )
        self.assertEqual(response.status_code, 401)


authorization_str: str | None = None


class WorkflowTest(IsolatedAsyncioTestCase):
    async def create_test_user(self):
        salt = ")mEzH=k-BU>poq%uz8=d"
        password = "realitycheck23"
        test_admin = User(
            username="test_admin",
            display_name="Test Admin",
            password_hash=User.create_password_hash(password, salt),
            salt=salt,
            email="test_admin@example.com",
        )
        root_project = Project(
            project_id="root",
            name="root",
            description="All projects must be ancestors of this project",
        )
        async with app.state.async_session() as session:
            # add admin
            session.add(test_admin)
            # add project
            session.add(root_project)
            # make admin a user in a project
            root_project.members.append(test_admin)
            # create role for a project
            role = Role(
                name="admin",
                project=root_project,
                permissions_api="superadmin",  # has no restrictions on api
            )
            session.add(role)
            # add a admin admin role
            role.users.append(test_admin)
            try:
                await session.commit()
            except IntegrityError:
                pass
        return password

    async def test_00_login_admin(self):
        password = await self.create_test_user()
        response = client.post(
            "/token",
            data={
                "username": "test_admin",
                "password": password,
            },
        )
        self.assertEqual(response.status_code, 200)
        token_body = response.json()
        self.assertIn("access_token", token_body)
        self.assertIn("token_type", token_body)
        global authorization_str
        authorization_str = f"{token_body['token_type'].capitalize()} {token_body['access_token']}"

    def test_01_whoami(self):
        assert isinstance(authorization_str, str), authorization_str
        response = client.get(
            "/whoami", headers={"Authorization": authorization_str}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "display_name": "Test Admin",
                "email": "test_admin@example.com",
                "username": "test_admin",
                "permissions_api": [["root", "superadmin"]],
            },
        )

    def test_02_add_project(self):
        assert isinstance(authorization_str, str), authorization_str
        project = {
            "project_id": "gmc",
            "name": "General Markup Creator",
            "description": "",
        }
        response = client.post(
            "/project",
            headers={"Authorization": authorization_str},
            json=project,
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json(), {"project_id": 2})
        response = client.post(
            "/project",
            headers={"Authorization": authorization_str},
            json=project,
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json(), {"detail": "project already exists"})

    async def test_03_edit_project(self):
        assert isinstance(authorization_str, str), authorization_str
        project = {
            "description": "Customizable MDI application",
        }
        response = client.patch(
            "/project/2",
            headers={"Authorization": authorization_str},
            json=project,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), None)
        async with app.state.async_session() as session:
            project_db = await session.get(Project, 2)
        self.assertEqual(project_db.description, project["description"])

    async def test_04_add_role(self):
        assert isinstance(authorization_str, str), authorization_str
        role = {
            "name": "test_role",
            "project_id": 2,
            "permissions_api": "user",
        }
        response = client.post(
            "/role",
            headers={"Authorization": authorization_str},
            json=role,
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json(), {"role_id": 2})

    async def test_05_update_role(self):
        assert isinstance(authorization_str, str), authorization_str
        role = {
            "description": "Update",
        }
        response = client.patch(
            "/role/2",
            headers={"Authorization": authorization_str},
            json=role,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), None)
        async with app.state.async_session() as session:
            role_db = await session.get(Role, 2)
        self.assertEqual(role_db.description, role["description"])
