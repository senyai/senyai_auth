from __future__ import annotations

import asyncio
import ssl
import logging
from argparse import ArgumentParser
from pydantic import BaseModel, Field
from .patched_aioftp_server import create_patched_server
from httpx import AsyncClient


class SSLConfig(BaseModel, strict=True):
    certfile: str = Field(
        examples=["/etc/letsencrypt/live/example.com/fullchain.pem"]
    )
    keyfile: str = Field(
        examples=["/etc/letsencrypt/live/example.com/privkey.pem"]
    )


class Config(BaseModel, strict=True):
    host: str = "127.0.0.1"
    port: int = 990
    drop_privileges_user: str | None = None
    ssl: SSLConfig | None = None
    greeting: str = Field("FTP Server Ready (PASV mode only)")
    base_path: str = Field(description="ftp root directory")
    ipv4_pasv_forced_response_address: str | None = Field(
        description="public port for ftp access"
    )
    data_ports: tuple[int, int] | None = Field(
        description="passive ports range [begin, end]"
    )
    api_url: str = "http://127.0.0.1:8000"


# configure root logger
logging.basicConfig(
    level=logging.DEBUG,  # DEBUG to see detailed protocol events
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

# optionally tune specific loggers
logging.getLogger("aioftp").setLevel(logging.DEBUG)
logging.getLogger("asyncio").setLevel(logging.INFO)


def create_ssl_context(config: SSLConfig):
    # Create a context for server-side sockets
    ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)

    # Load server certificate and private key
    ctx.load_cert_chain(certfile=config.certfile, keyfile=config.keyfile)

    # Optional: require and verify client certificates (mutual TLS)
    # ctx.verify_mode = ssl.CERT_REQUIRED
    # ctx.load_verify_locations(cafile="ca_clients.pem")

    # Enforce TLS versions and strong ciphers
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:!aNULL:!eNULL:!LOW:!3DES:!MD5")

    # Disable insecure legacy options (mostly set by create_default_context already)
    # ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_COMPRESSION

    return ctx


def drop_privileges(username: str) -> None:
    import pwd, os

    pw = pwd.getpwnam(username)
    target_uid = pw.pw_uid
    target_gid = pw.pw_gid
    os.setgroups([])  # or [gid1, gid2] if needed
    os.setgid(target_gid)  # set GID first
    os.setuid(target_uid)  # then set UID


async def _server_main(config: Config):
    async with AsyncClient(base_url=config.api_url) as api_client:
        server = create_patched_server(
            api_client,
            ssl=config.ssl and create_ssl_context(config.ssl),
            ipv4_pasv_forced_response_address=config.ipv4_pasv_forced_response_address,
            data_ports=config.data_ports,
            greeting_message=config.greeting,
        )
        await server.start(host=config.host, port=config.port)
        if config.drop_privileges_user is not None:
            drop_privileges(config.drop_privileges_user)
        try:
            await server.serve_forever()
        finally:
            await server.close()
    print("done!")


def main():
    parser = ArgumentParser()
    parser.add_argument("config", nargs="?", default="config_ftp.json")
    args = parser.parse_args()
    with open(args.config) as f:
        config = Config.model_validate_json(f.read())
    asyncio.run(_server_main(config))


if __name__ == "__main__":
    main()
