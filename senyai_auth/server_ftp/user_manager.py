from __future__ import annotations
from pathlib import Path, PurePosixPath
from aioftp.server import AbstractUserManager, Permission, AvailableConnections
import httpx


class User:
    def __init__(self, login: str, base_path: Path) -> None:
        self.login = login
        self.base_path = base_path

    def after_login(self, permissions: list[Permission]) -> None:
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
        self,
        client: httpx.AsyncClient,
        basepath: Path,
        timeout: float | int | None = None,
    ) -> None:
        super().__init__(timeout=timeout)
        self._basepath = basepath
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
                User(login, self._basepath),
                f"too much connections for {login!r}",
            )
        return (
            AbstractUserManager.GetUserResponse.PASSWORD_REQUIRED,
            User(login, self._basepath),
            "password required",
        )

    async def authenticate(self, user: User, password: str) -> bool:
        if user.login not in self.available_connections:
            max_connections = 3
            self.available_connections[user.login] = AvailableConnections(
                max_connections
            )
        self.available_connections[user.login].acquire()
        try:
            token_res = await self._client.post(
                "/token",
                data={
                    "username": user.login,
                    "password": password,
                },
            )
            if token_res.status_code != 200:  # invalid credentials
                return False
            token = token_res.json()
            authorization_str = (
                f"{token['token_type'].capitalize()} {token['access_token']}"
            )
            # now retrieve permissions
            permissions_res = await self._client.get(
                "/ldap/roles/storage",
                headers={"Authorization": authorization_str},
            )
            if permissions_res.status_code != 200:  # nothing is available
                return False
            permissions: list[Permission] = []
            for path_right in permissions_res.json():
                path, _, rights = path_right.rpartition(":")
                permissions.append(
                    Permission(
                        f"/{path}", readable=True, writable=rights == "w"
                    )
                )
                print("Added", permissions[-1])
            user.permissions = permissions
        except httpx.NetworkError as e:
            print(f"authentication server not available {e}")
            return False
        return True

    async def notify_logout(self, user: User) -> None:
        self.available_connections[user.login].release()
