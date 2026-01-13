from __future__ import annotations

import asyncio
import aioftp


async def main():
    users = [
        aioftp.User(
            "senyai",
            "lol",
            base_path="ftp_root",
            permissions=(
                aioftp.Permission("/", readable=False, writable=False),
                aioftp.Permission("/a", readable=True, writable=False),
            ),
        )
    ]

    server = aioftp.Server(users)
    await server.run(host="127.0.0.1", port=8025)
    print("done!")


asyncio.run(main())
