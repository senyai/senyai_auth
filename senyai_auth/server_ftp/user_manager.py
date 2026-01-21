from __future__ import annotations
from pathlib import PurePosixPath
from aioftp.server import AbstractUserManager, Permission, AvailableConnections
import httpx


class User:
    def __init__(self, login: str):
        self.login = login

    def after_login(self, permissions: list[Permission]):
        self.permissions = permissions

    async def get_permissions(self, path: str | PurePosixPath) -> Permission:
        path = PurePosixPath(path)
        parents = filter(lambda p: p.is_parent(path), self.permissions)
        perm = min(
            parents,
            key=lambda p: len(path.relative_to(p.path).parts),
            default=Permission(),
        )
        return perm


class UserManager(AbstractUserManager):
    def __init__(
        self, client: httpx.AsyncClient, timeout: float | int | None = None
    ) -> None:
        super().__init__(timeout=timeout)
        self._client = client
        self.available_connections: dict[str, AvailableConnections] = {}

    async def get_user(
        self, login: str
    ) -> tuple[AbstractUserManager.GetUserResponse, User | None, str]:
        if (
            login in self.available_connections
            and self.available_connections[login].locked()
        ):
            return (
                AbstractUserManager.GetUserResponse.ERROR,
                User(login),
                f"too much connections for {login!r}",
            )
        return (
            AbstractUserManager.GetUserResponse.PASSWORD_REQUIRED,
            User(login),
            "password required",
        )

    async def authenticate(self, user: User, password: str) -> bool:
        self.available_connections[user.login].acquire()
        try:
            token_res = await self._client.post(
                "/token",
                data={
                    "username": user.login,
                    "password": password,
                },
            )
            if token_res.status_code != 200:  # login and password are valid.
                return False
            token = token_res.json()
            authorization_str = (
                f"{token['token_type'].capitalize()} {token['access_token']}"
            )
            # now retrieve permissions
            permissions_res = await self._client.get(
                "/permissions/storage",
                headers={"Authorization": authorization_str},
            )
            permissions: list[Permission] = []
            for path_right in permissions_res.json():
                path, _, rights = path_right.rpartition(":")
                permissions.append(
                    Permission(path, readable=True, writable=rights == "w")
                )
            user.permissions = permissions
        except Exception as e:
            print(f"authentication server not available {e}")
            return False
        return True

    async def notify_logout(self, user: User) -> None:
        self.available_connections[user.login].release()
