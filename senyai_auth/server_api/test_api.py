from __future__ import annotations
from fastapi.testclient import TestClient
from fastapi import status
from unittest import TestCase, IsolatedAsyncioTestCase
from sqlalchemy.exc import IntegrityError

from . import app, get_settings, AppSettings
from .db import Project, Role, User, PermissionsAPI


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
            ("/user", "get"),
            ("/", "get"),
            ("/user", "post"),
            ("/user/1", "delete"),
            ("/user/1", "patch"),
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
invitation_str: str | None = None


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
            name="root",
            display_name="root",
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
                permissions_api=PermissionsAPI.superadmin,  # has no restrictions on api
            )
            session.add(role)
            # add a admin admin role
            role.members.append(test_admin)
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
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        token_body = response.json()
        self.assertIn("access_token", token_body)
        self.assertIn("token_type", token_body)
        global authorization_str
        authorization_str = f"{token_body['token_type'].capitalize()} {token_body['access_token']}"

    def test_01_whoami(self):
        assert isinstance(authorization_str, str), authorization_str
        response = client.get(
            "/user", headers={"Authorization": authorization_str}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.json(),
            {
                "id": 1,
                "display_name": "Test Admin",
                "email": "test_admin@example.com",
                "username": "test_admin",
                "permissions_api": [["root", "superadmin"]],
                "contacts": "",
            },
        )

    def test_02_add_project(self):
        assert isinstance(authorization_str, str), authorization_str
        project = {
            "name": "gmc",
            "display_name": "General Markup Creator",
            "description": "",
            "parent_id": 1,
        }
        response = client.post(
            "/project",
            headers={"Authorization": authorization_str},
            json=project,
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.json(), {"project_id": 2})
        response = client.post(
            "/project",
            headers={"Authorization": authorization_str},
            json=project,
        )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(
            response.json(), {"detail": "Project 'gmc' already exists"}
        )

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
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(response.content, b"")
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
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
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
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(response.content, b"")
        async with app.state.async_session() as session:
            role_db = await session.get(Role, 2)
        self.assertEqual(role_db.description, role["description"])

    async def test_06_create_admin_for_project(self):
        assert isinstance(authorization_str, str), authorization_str
        user = {
            "username": "john",
            "password": "jiBBerish",
            "display_name": "John Blackpool",
            "email": "johnnyB@example.com",
            "contacts": "HQ",
        }
        response = client.post(
            "/user",
            headers={"Authorization": authorization_str},
            json=user,
        )
        self.assertEqual(response.json(), {"user_id": 2})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    async def test_07_add_admin_for_project(self):
        assert isinstance(authorization_str, str), authorization_str
        users = [2]
        response = client.post(
            "/role/2/users",
            headers={"Authorization": authorization_str},
            json=users,
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.content, b"")

    async def test_08_admin_creates_invitation(self):
        assert isinstance(authorization_str, str), authorization_str
        invitation = {
            "project_id": 2,
            "prompt": "Welcome",
            "default_username": "newuser",
            "default_email": "newuser@example.com",
            "default_display_name": "New User",
        }
        response = client.post(
            "/invite",
            headers={"Authorization": authorization_str},
            json=invitation,
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        json = response.json()
        self.assertIn("url_key", json)
        self.assertEqual(len(json["url_key"]), 32)
        global invitation_str
        invitation_str = json["url_key"]

    async def test_09_user_gets_invitation(self):
        response = client.get(f"/invite/{invitation_str}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.json(),
            {
                "display_name": "New User",
                "email": "newuser@example.com",
                "prompt": "Welcome",
                "username": "newuser",
            },
        )

    async def test_10_user_accepts_invitation(self):
        user = {
            "username": "invited_user",
            "password": "milkshape3000",
            "display_name": "Invited User",
            "email": "ted@example.com",
            "contacts": "home address",
        }
        response = client.post(f"/register/{invitation_str}", json=user)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.json(), {"user_id": 3})

    async def test_11_admin_lists_invitations(self):
        assert isinstance(authorization_str, str), authorization_str
        project_id = 2
        response = client.get(
            f"/invites/{project_id}",
            headers={"Authorization": authorization_str},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.json(),
            [
                {
                    "accepted_id": 3,
                    "display_name": "New User",
                    "url_key": invitation_str,
                }
            ],
        )

    async def test_20_delete_admin_from_project(self):
        assert isinstance(authorization_str, str), authorization_str
        users = [2]
        response = client.request(
            "DELETE",
            "/role/2/users",
            headers={"Authorization": authorization_str},
            json=users,
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(response.content, b"")


class Z_UserUpdateTest(IsolatedAsyncioTestCase):
    async def login(self, username: str, password: str) -> str:
        response = client.post(
            "/token",
            data={
                "username": username,
                "password": password,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        token_body = response.json()
        self.assertIn("access_token", token_body)
        self.assertIn("token_type", token_body)
        return f"{token_body['token_type'].capitalize()} {token_body['access_token']}"

    async def change_display_name(self, authorization_str: str) -> int:
        my_id: int = client.get(
            "/user", headers={"Authorization": authorization_str}
        ).json()["id"]
        response = client.patch(
            f"/user/{my_id}",
            json={"display_name": "Mike Buginsky"},
            headers={"Authorization": authorization_str},
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        new_display_name = client.get(
            "/user", headers={"Authorization": authorization_str}
        ).json()["display_name"]
        self.assertEqual(new_display_name, "Mike Buginsky")
        return my_id

    async def change_password(
        self, authorization_str: str, my_id: int
    ) -> None:
        response = client.patch(
            f"/user/{my_id}",
            json={
                "password": {"old": "milkshape3000", "new": "milkshape3001"}
            },
            headers={"Authorization": authorization_str},
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        response = client.get(
            "/user", headers={"Authorization": authorization_str}
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    async def must_provide_original_password(
        self, authorization_str: str, my_id: int
    ) -> None:
        response = client.patch(
            f"/user/{my_id}",
            json={"password": {"old": "milkshape300", "new": "milkshape3001"}},
            headers={"Authorization": authorization_str},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.json(), {"detail": "Current password does not match"}
        )

    async def cant_change_username(
        self, authorization_str: str, my_id: int
    ) -> None:
        response = client.patch(
            f"/user/{my_id}",
            json={"username": "sly_fox"},
            headers={"Authorization": authorization_str},
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            response.json(),
            {"detail": "Only Administrator can change user's username"},
        )

    async def test(self):
        authorization_str = await self.login(
            username="invited_user", password="milkshape3000"
        )
        my_id = await self.change_display_name(authorization_str)
        await self.must_provide_original_password(authorization_str, my_id)
        await self.cant_change_username(authorization_str, my_id)
        await self.change_password(authorization_str, my_id)
