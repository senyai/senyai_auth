from __future__ import annotations

import asyncio
import ssl
from pathlib import PurePosixPath
import httpx
from aioftp.common import Connection, END_OF_LINE
from aioftp.server import (
    AbstractUserManager,
    ConnectionConditions,
    PathConditions,
    PathPermissions,
    Server,
    worker,
)
from .user_manager import UserManager


@ConnectionConditions(
    ConnectionConditions.login_required,
    ConnectionConditions.passive_server_started,
)
@PathConditions(PathConditions.path_must_exists)
@PathPermissions(PathPermissions.readable)
async def nlst(
    self: Server, connection: Connection, rest: str | PurePosixPath
) -> bool:
    @ConnectionConditions(
        ConnectionConditions.data_connection_made,
        wait=True,
        fail_code="425",
        fail_info="Can't open data connection",
    )
    @worker
    async def nlst_worker(
        self: "Server", connection: Connection, rest: str | PurePosixPath
    ) -> bool:
        stream = connection.data_connection
        del connection.data_connection
        async with stream:
            async for path in connection.path_io.list(real_path):
                b = (path.name + END_OF_LINE).encode(encoding=self.encoding)
                await stream.write(b)
        connection.response("200", "nlst transfer done")
        return True

    real_path, virtual_path = self.get_paths(connection, rest)
    coro = nlst_worker(self, connection, rest)
    task: asyncio.Task[bool] = asyncio.create_task(coro)  # type: ignore[arg-type]
    connection.extra_workers.add(task)
    connection.response("150", "nlst transfer started")
    return True


@ConnectionConditions(ConnectionConditions.login_required)
async def port(
    self: Server, connection: Connection, rest: str | PurePosixPath
) -> bool:
    connection.response(
        "500", "PORT command not supported. Use PASV mode only"
    )
    return True


@ConnectionConditions(ConnectionConditions.login_required)
async def clnt(
    self: Server, connection: Connection, rest: str | PurePosixPath
) -> bool:
    connection.response("200", "OK")
    return True


@ConnectionConditions(ConnectionConditions.login_required)
async def opts(
    self: Server, connection: Connection, rest: str | PurePosixPath
) -> bool:
    key, value = rest.split(" ", 2)
    connection.response("200", f"{key} set to {value}")
    return True


@ConnectionConditions(ConnectionConditions.login_required)
async def feat(
    self: Server, connection: Connection, rest: str | PurePosixPath
) -> bool:
    features = (
        "Features:",
        "CLNT",
        "EPRT",
        "EPSV",
        "HOST",
        "LANG en-US.UTF-8*;en-US",
        # "MDTM",
        "SITE MKDIR",
        "SITE RMDIR",
        "SITE SYMLINK",
        "SITE UTIME",
        "MFMT",
        "SIZE",
        "UTF8",
        "End",
    )
    connection.response("211", features, True)
    return True


async def greeting(
    self: Server, connection: Connection, rest: str | PurePosixPath
) -> bool:
    if self.available_connections.locked():
        ok, code, info = False, "421", "Too many connections"
    else:
        ok, code, info = (
            True,
            "220",
            self.greeting_message,
        )
        connection.acquired = True
        self.available_connections.acquire()
    connection.response(code, info)
    return ok


async def user(self: Server, connection: Connection, rest: str) -> bool:
    if connection.future.user.done():
        await self.user_manager.notify_logout(connection.user)
    del connection.user
    del connection.logged
    state, user, info = await self.user_manager.get_user(rest)
    assert state == AbstractUserManager.GetUserResponse.PASSWORD_REQUIRED
    code = "331"
    connection.user = user
    connection.current_directory = PurePosixPath("/")
    connection.response(code, info)
    return True


def create_patched_server(
    api_client: httpx.AsyncClient,
    *,
    ipv4_pasv_forced_response_address: str | None = None,
    data_ports: tuple[int, int] | None = None,
    ssl: ssl.SSLContext | None = None,
    greeting_message: str = "welcome",
) -> Server:
    Server.greeting = greeting
    Server.user = user
    user_manager = UserManager(api_client)
    server = Server(
        user_manager,
        ssl=ssl,
        ipv4_pasv_forced_response_address=ipv4_pasv_forced_response_address,
        data_ports=data_ports and range(data_ports[0], data_ports[1] + 1),
    )
    server.greeting_message = greeting_message
    Server.nlst = nlst
    Server.port = port
    Server.feat = feat
    Server.clnt = clnt
    Server.opts = opts
    server.commands_mapping["nlst"] = server.nlst
    server.commands_mapping["port"] = server.port
    server.commands_mapping["feat"] = server.feat
    server.commands_mapping["clnt"] = server.clnt
    server.commands_mapping["opts"] = server.opts
    return server
