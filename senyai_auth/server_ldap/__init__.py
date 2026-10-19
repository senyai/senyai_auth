from __future__ import annotations
from typing import cast, NamedTuple, ClassVar

# https://lapo.it/asn1js/#MEICAQFgPQIBAwQqY249TWFuYWdlcixkYz1jc2M5NSxkYz1zZS12aS1zY2llbmNlLGRjPXJ1gAxyMDB0UGFTc3cwckQ
# https://raw.githubusercontent.com/emrig/w4156-PEAS-Oktave/76d0cce1ab4c8e529ad49dd20b50ab73ca018ce2/g/pyasn1_modules/rfc2251.py
# https://raw.githubusercontent.com/pyasn1/pyasn1-modules/02f9c577bcd0ad9fedfb0fd5dc598d323f7984bf/pyasn1_modules/rfc2251.py

from asyncio import (
    create_task,
    start_server,
    StreamReader,
    StreamWriter,
    IncompleteReadError,
    run as asyncio_run,
)
import json
from httpx2 import AsyncClient, AsyncBaseTransport
from pyasn1.type import univ, namedtype
from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import EndOfStreamError, PyAsn1Error
from .bind import (
    BindRequest,
    BindResponse,
    clear_cache_periodically,
    UnbindRequest,
)
from .search import SearchRequest, SearchResultEntry, SearchResultDone
from .logger import create_logger
from .ldap_types import LDAPMessage

logger = create_logger(__name__)


class Domain(NamedTuple):
    name: str  # example.com
    components: tuple[bytes, ...]  # (b"example", b"com")
    dc: str  # "dc=example,dc=com"

    @classmethod
    def make(cls, name: str):
        return Domain(
            name=name,
            components=tuple(name.encode().split(b".")),
            dc=",".join(f"dc={part}" for part in name.split(".")),
        )


DOMAIN = Domain.make("example.com")


class MessageID(univ.Integer):
    pass


LDAPMessage.componentType = namedtype.NamedTypes(
    namedtype.NamedType("messageID", MessageID()),
    namedtype.NamedType(
        "protocolOp",  # univ.Any()
        univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("bindRequest", BindRequest()),
                namedtype.NamedType("bindResponse", BindResponse()),
                namedtype.NamedType("unbindRequest", UnbindRequest()),
                namedtype.NamedType("searchRequest", SearchRequest()),
                namedtype.NamedType("searchResEntry", SearchResultEntry()),
                namedtype.NamedType("searchResDone", SearchResultDone()),
                # namedtype.NamedType('searchResRef', SearchResultReference()),
                # namedtype.NamedType('modifyRequest', ModifyRequest()),
                # namedtype.NamedType('modifyResponse', ModifyResponse()),
                # namedtype.NamedType('addRequest', AddRequest()),
                # namedtype.NamedType('addResponse', AddResponse()),
                # namedtype.NamedType('delRequest', DelRequest()),
                # namedtype.NamedType('delResponse', DelResponse()),
                # namedtype.NamedType('modDNRequest', ModifyDNRequest()),
                # namedtype.NamedType('modDNResponse', ModifyDNResponse()),
                # namedtype.NamedType('compareRequest', CompareRequest()),
                # namedtype.NamedType('compareResponse', CompareResponse()),
                # namedtype.NamedType('abandonRequest', AbandonRequest()),
                # namedtype.NamedType('extendedReq', ExtendedRequest()),
                # namedtype.NamedType('extendedResp', ExtendedResponse())
            )
        ),
    ),
    namedtype.OptionalNamedType("controls", univ.Any()),
)


# --- Connection handler ---
class LDAPProtocol:
    base_url: ClassVar[str]  # API path
    usernames: ClassVar[set[str]]  # cache these username bind requests

    @classmethod
    async def handle_client(
        cls,
        reader: StreamReader,
        writer: StreamWriter,
        transport: AsyncBaseTransport | None = None,
    ) -> None:
        self = cls()
        peername = writer.get_extra_info("peername")
        logger.info(f"New connection from: {peername}")
        try:
            async with AsyncClient(
                base_url=self.base_url, transport=transport
            ) as api_client:
                await self.run(api_client, reader, writer)
        finally:
            writer.close()
            await writer.wait_closed()

    @classmethod
    async def run(
        cls,
        api_client: AsyncClient,
        reader: StreamReader,
        writer: StreamWriter,
    ) -> None:
        try:
            async for ldap_message in cls._parse_messages(reader):
                await cls._handle_message(ldap_message, api_client, writer)
        except IncompleteReadError:
            pass

    @staticmethod
    async def _parse_messages(reader: StreamReader):
        buf = b""
        while chunk := await reader.read(4096):
            buf += chunk
            try:
                ldap_message, buf = cast(
                    tuple[LDAPMessage, bytes],
                    decoder.decode(buf, asn1Spec=LDAPMessage()),
                )
                yield ldap_message
            except EndOfStreamError:
                # need more data; continue reading
                continue
            except PyAsn1Error:
                # standard way is to ignore it and disconnect
                logger.info("client error: bad `LDAPMessage`")
                break

    @staticmethod
    async def _handle_message(
        lm: LDAPMessage, api_client: AsyncClient, writer: StreamWriter
    ) -> None:
        msgid = int(lm.getComponentByName("messageID"))
        op = lm.getComponentByName("protocolOp")
        component = cast(
            BindRequest | UnbindRequest | SearchRequest, op.getComponent()
        )
        async for ldap_message in component.process(api_client):
            ldap_message.setComponentByName("messageID", msgid)
            writer.write(encoder.encode(ldap_message))
        await writer.drain()


async def _server_main(
    host: str, port: int, api_url: str, usernames: set[str]
) -> None:
    LDAPProtocol.base_url = api_url.rstrip("/")
    BindRequest.usernames = usernames
    server = await start_server(LDAPProtocol.handle_client, host, port)
    addr = server.sockets[0].getsockname()
    logger.info(
        f"{__name__} server listening on {addr} and serving {DOMAIN.name}"
    )
    logger.info(f"with api at {LDAPProtocol.base_url}")
    task = create_task(clear_cache_periodically())
    try:
        async with server:
            await server.serve_forever()
    finally:
        task.cancel()


def main():
    from argparse import ArgumentParser
    import os

    settings_path = os.getenv("AUTH_LDAP_SETTINGS_PATH", "settings_ldap.json")

    with open(settings_path) as f:
        default_settings = json.load(f)
    parser = ArgumentParser()
    help = "default: %(default)s"
    parser.set_defaults(
        host=default_settings.pop("host", "127.0.0.1"),
        port=default_settings.pop("port", 10389),
        api_url=default_settings.pop("api_url", "http://127.0.0.1:8000"),
        domain=default_settings.pop("domain", "example.com"),
    )
    parser.add_argument("--host", help=help)
    parser.add_argument("--port", "-p", type=int, help=help)
    parser.add_argument("--domain", "-d", help=help)
    parser.add_argument("--api-url", "-a", help=help)
    parser.add_argument(
        "--username",
        "-u",
        dest="usernames",
        help=f"{help}, usernames to cache",
        nargs="*",
        default=[],
    )
    args = vars(parser.parse_args())
    args["usernames"] = str(args["usernames"])

    global DOMAIN
    DOMAIN = Domain.make(args.pop("domain"))
    assert not default_settings, f"Extra settings {default_settings}"

    asyncio_run(_server_main(**args))


if __name__ == "__main__":
    main()
