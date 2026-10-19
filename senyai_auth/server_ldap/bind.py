from __future__ import annotations
from typing import cast, NewType, AsyncGenerator, ClassVar
from time import monotonic
from asyncio import Future, get_running_loop, sleep
from httpx2 import AsyncClient, ConnectError
from pyasn1.type import univ, tag, namedtype, namedval
from .ldap import parse_dn, DN
from .ldap_types import LDAPString, LDAPMessage
from .. import server_ldap
from .logger import create_logger

logger = create_logger(__name__)
Bearer = NewType("Bearer", str)
bearer_cache: dict[tuple[str, str], tuple[float, Future[Bearer | None]]] = {}


class SaslCredentials(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("mechanism", LDAPString()),
        namedtype.OptionalNamedType("credentials", univ.OctetString()),
    )


class AuthenticationChoice(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "simple",
            univ.OctetString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0
                )
            ),
        ),
        namedtype.NamedType(
            "reserved-1",
            univ.OctetString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 1
                )
            ),
        ),
        namedtype.NamedType(
            "reserved-2",
            univ.OctetString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 2
                )
            ),
        ),
        namedtype.NamedType(
            "sasl",
            SaslCredentials().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 3
                )
            ),
        ),
    )


class BindRequest(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "version",
            univ.Integer(),
        ),
        namedtype.NamedType("name", univ.OctetString()),
        namedtype.NamedType("authentication", AuthenticationChoice()),
    )
    usernames: ClassVar[set[str]]

    async def process(
        self, api_client: AsyncClient
    ) -> AsyncGenerator[LDAPMessage, None]:
        async for _ in UnbindRequest.process(api_client):
            pass
        # api_client.headers.pop("Authorization", None)  # just in case
        dn_bytes = self.getComponentByName("name").asOctets()
        assert isinstance(dn_bytes, bytes)
        dn = parse_dn(dn_bytes)
        password = cast(
            bytes,
            (
                self.getComponentByName("authentication")
                .getComponentByName("simple")
                .asOctets()
            ),
        )
        if dn.domain_components != server_ldap.DOMAIN.components:
            yield _create_bind_response(
                result=49,
                matchedDN=b"",
                diag="invalid domain",
            )
            logger.info(f"client error: invalid domain {dn.domain_components}")
            return
        if dn.user_name is None:
            yield _create_bind_response(
                result=49,
                matchedDN=b"",
                diag="missing uid",
            )
            logger.info("client error: no uid")
            return
        username, password = cache_key = (
            dn.user_name.decode(),
            password.decode(),
        )
        now = monotonic()
        if username in self.usernames and cache_key in bearer_cache:
            expiration, bearer_promise = bearer_cache[cache_key]
            if expiration > now or not bearer_promise.done():  # not expired
                bearer = await bearer_promise
                if bearer is not None:
                    yield self._successful_auth(
                        api_client, dn, bearer, "cache"
                    )
                return
            del bearer_cache[cache_key]
        try:
            response = await api_client.post(
                "/token",
                headers={},
                data={"username": username, "password": password},
            )
        except ConnectError as e:
            yield _create_bind_response(
                result=49,
                matchedDN=b"",
                diag=f"api backend down ({e})",
            )
            logger.info("server error: post: {e}")
            return
        future: Future[Bearer | None] = get_running_loop().create_future()
        bearer_cache[cache_key] = now + 10.0, future
        if response.status_code == 200:
            token_body = response.json()
            bearer = Bearer(
                f"{token_body['token_type'].capitalize()} "
                f"{token_body['access_token']}"
            )
            # for admin users that
            bearer_cache[cache_key] = now + 60.0 * 60.0 * 24, future
            future.set_result(bearer)
            yield self._successful_auth(api_client, dn, bearer, "api")
        else:
            future.set_result(None)
            logger.info(
                "client error: failed to authorize "
                f"'{username}': {response.status_code}"
            )
            yield _create_bind_response(
                result=49,
                matchedDN=dn_bytes,
                diag=f"invalid credentials {response.status_code}",
            )

    @staticmethod
    def _successful_auth(
        api_client: AsyncClient, dn: DN, bearer: Bearer, reason: str
    ) -> LDAPMessage:
        logger.info(f"client: authorized {dn.user_name}")
        api_client.headers["Authorization"] = bearer
        return _create_bind_response(matchedDN=dn.dn, diag=reason)


class UnbindRequest(univ.Null):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 2)
    )

    @staticmethod
    async def process(
        api_client: AsyncClient,
    ) -> AsyncGenerator[LDAPMessage, None]:
        api_client.headers.pop("Authorization", None)
        if False:
            yield


# BindResponse-like result
class ResultCode(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ("success", 0), ("invalidCredentials", 49), ("operationsError", 1)
    )


class BindResponse(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 1)
    )

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("resultCode", ResultCode()),
        namedtype.NamedType("matchedDN", LDAPString()),
        namedtype.NamedType("diagnosticMessage", LDAPString()),
    )


def _create_bind_response(
    result: int = 0, matchedDN: bytes = b"", diag: str = ""
) -> LDAPMessage:
    br = BindResponse()
    br.setComponentByName("resultCode", result)
    br.setComponentByName("matchedDN", matchedDN.decode())
    br.setComponentByName("diagnosticMessage", diag)
    lm = LDAPMessage()
    lm["protocolOp"].setComponentByName("bindResponse", br)
    return lm


async def clear_cache_periodically() -> None:
    while True:
        await sleep(60.0)
        now = monotonic()
        keys = [
            key
            for key, (expiration, promise) in bearer_cache.items()
            if expiration < now and promise.done()  # expired  # and ready
        ]
        for key in keys:
            del bearer_cache[key]
