from __future__ import annotations
from typing import cast, Callable, TypeAlias, Literal
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock
from httpx2 import Response, Request, MockTransport, AsyncBaseTransport

from . import LDAPMessage, LDAPProtocol
from .bind import AuthenticationChoice, BindRequest
from .search import (
    Attribute,
    AttributeDescriptionList,
    AttributeValue,
    Filter,
    PartialAttributeList,
    SearchRequest,
)
import asyncio
from pyasn1.codec.ber import encoder as ber_encoder
from pyasn1.type import univ

LDAPProtocol.base_url = "http://127.0.0.1/unittest"
InitFilter: TypeAlias = Callable[[Filter], None]


def _create_bind_request(*, msgid: int, name: str) -> LDAPMessage:
    ldap_message = LDAPMessage()
    ldap_message.setComponentByName("messageID", msgid)
    br = ldap_message["protocolOp"].getComponentByName("bindRequest")
    br.setComponentByName("version", 1)
    br.setComponentByName("name", name)
    ac = AuthenticationChoice()
    ac.setComponentByName("simple", "pa$$word")
    br.setComponentByName("authentication", ac)
    return ldap_message


def _create_bind_response(
    *, msgid: int, result: int, matchedDN: bytes, diag: str
) -> LDAPMessage:
    ldap_message = LDAPMessage()
    ldap_message.setComponentByName("messageID", msgid)
    br = ldap_message["protocolOp"].getComponentByName("bindResponse")
    br.setComponentByName("resultCode", result)
    br.setComponentByName("matchedDN", matchedDN.decode())
    br.setComponentByName("diagnosticMessage", diag)
    return ldap_message


async def _send(
    *ldap_message: LDAPMessage,
    transport: AsyncBaseTransport | None = None,
) -> list[bytes]:
    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.get_extra_info.side_effect = ("test_client",)
    reader.read.side_effect = [
        cast(bytes, ber_encoder.encode(lm)) for lm in ldap_message
    ] + [b""]
    await LDAPProtocol.handle_client(reader, writer, transport=transport)
    writer.write.assert_called()
    writer.close.assert_called()

    return [a.args[0] for a in writer.write.call_args_list]


class CompareTest(IsolatedAsyncioTestCase):
    maxDiff = 4000

    def _compare(self, exps: list[bytes], refs: list[LDAPMessage]) -> None:
        for exp_ber, ref in zip(exps, refs, strict=True):
            ref_ber = cast(bytes, ber_encoder.encode(ref))
            if exp_ber != ref_ber:
                print("EXP", exp_ber.hex())
            self.assertEqual(exp_ber.hex(), ref_ber.hex())


class BindTest(CompareTest):
    async def test_invalid_domain(self) -> None:
        msg = _create_bind_request(msgid=1, name="what")
        answers = await _send(msg)
        ref_lm = _create_bind_response(
            msgid=1, result=49, matchedDN=b"", diag="invalid domain"
        )
        self._compare(answers, [ref_lm])

    async def test_missing_username(self) -> None:
        msg = _create_bind_request(msgid=2, name="dc=example,dc=com")
        answers = await _send(msg)
        ref_lm = _create_bind_response(
            msgid=2, result=49, matchedDN=b"", diag="missing uid"
        )
        self._compare(answers, [ref_lm])

    async def test_invalid_auth(self) -> None:
        BindRequest.usernames = {"user3"}
        msg = _create_bind_request(msgid=3, name="uid=error,dc=example,dc=com")
        transport = MockTransport(lambda _request: Response(401))
        answers = await _send(msg, transport=transport)
        ref_lm = _create_bind_response(
            msgid=3,
            result=49,
            matchedDN=b"uid=error,dc=example,dc=com",
            diag="invalid credentials 401",
        )
        self._compare(answers, [ref_lm])

    async def test_successful_bind(self) -> None:
        BindRequest.usernames = {"user3"}
        msg = _create_bind_request(msgid=4, name="uid=user3,dc=example,dc=com")

        def on_request(request: Request) -> Response:
            self.assertEqual(
                request.content, b"username=user3&password=pa%24%24word"
            )
            self.assertEqual(request.method, "POST")
            return Response(
                200, json={"token_type": "Bearer", "access_token": "my_token"}
            )

        transport = MockTransport(on_request)
        answers = await _send(msg, msg, transport=transport)
        ref_lm = _create_bind_response(
            msgid=4,
            result=0,
            matchedDN=b"uid=user3,dc=example,dc=com",
            diag="api",
        )
        ref_lm_2 = _create_bind_response(
            msgid=4,
            result=0,
            matchedDN=b"uid=user3,dc=example,dc=com",
            diag="cache",
        )
        self._compare(answers, [ref_lm, ref_lm_2])


def _filter_match(filter: Filter, desc: str, value: str) -> None:
    eq_match = filter.getComponentByName("equalityMatch")
    eq_match.setComponentByName("attributeDesc", desc)
    eq_match.setComponentByName("assertionValue", value)


def _filter_create(
    filter: Filter, op: Literal["and", "or"], ops: list[InitFilter]
) -> None:
    and_match = filter.getComponentByName(op)

    for idx, op in enumerate(ops):
        sub_filter = Filter()
        op(sub_filter)
        and_match.setComponentByPosition(idx, sub_filter)


def _filter_user(filter: Filter, *, username: str) -> None:
    _filter_create(
        filter,
        "and",
        ops=[
            lambda f: _filter_match(f, "objectClass", value="account"),
            lambda f: _filter_create(
                f,
                "or",
                ops=[
                    lambda f: _filter_match(f, "uid", value=username),
                    lambda f: _filter_match(f, "mail", value=username),
                ],
            ),
        ],
    )


def _create_search_request(
    *, msgid: int, base_object: str, init_filter: InitFilter
) -> LDAPMessage:
    sr = SearchRequest()
    sr.setComponentByName("baseObject", base_object)
    sr.setComponentByName("scope", 2)  # not implemented yet
    sr.setComponentByName("derefAliases", 0)
    sr.setComponentByName("sizeLimit", 0)
    sr.setComponentByName("timeLimit", 0)
    sr.setComponentByName("typesOnly", False)
    attr_list = AttributeDescriptionList()
    sr.setComponentByName("attributes", attr_list)

    filter_obj = Filter()
    init_filter(filter_obj)
    sr.setComponentByName("filter", filter_obj)

    ldap_message = LDAPMessage()
    ldap_message.setComponentByName("messageID", msgid)
    ldap_message["protocolOp"].setComponentByName("searchRequest", sr)
    return ldap_message


def _create_search_result_done(
    *,
    msgid: int,
    result_code: int,
    diag: str,
) -> LDAPMessage:
    ldap_message = LDAPMessage()
    ldap_message.setComponentByName("messageID", msgid)
    srd = ldap_message["protocolOp"].getComponentByName("searchResDone")
    srd["resultCode"] = result_code
    srd["matchedDN"] = b""
    srd["diagnosticMessage"] = diag
    return ldap_message


def _create_search_result_entry(
    *, msgid: int, dn: str, attributes: dict[bytes, bytes | list[bytes]]
) -> LDAPMessage:
    """Encode a SearchResultEntry response"""

    ldap_message = LDAPMessage()
    ldap_message.setComponentByName("messageID", msgid)
    sre = ldap_message["protocolOp"].getComponentByName("searchResEntry")

    sre["objectName"] = dn

    attrs_seq = PartialAttributeList()

    for attr_type, values in attributes.items():
        attr = Attribute()
        attr["type"] = attr_type

        vals_set = univ.SetOf(componentType=AttributeValue())
        for value in values if isinstance(values, list) else [values]:
            vals_set.append(value)

        attr["vals"] = vals_set
        attrs_seq.append(attr)

    sre["attributes"] = attrs_seq
    return ldap_message


class SearchTest(CompareTest):
    async def test_invalid_domain(self):
        msg = _create_search_request(
            msgid=4,
            init_filter=lambda f: _filter_match(f, "", ""),
            base_object="",
        )
        answers = await _send(msg)
        ref_lm = _create_search_result_done(
            msgid=4, result_code=1, diag="Invalid domain ()"
        )
        self._compare(answers, [ref_lm])

    async def test_not_implemented(self):
        msg = _create_search_request(
            msgid=5,
            base_object="uid=no-impl,dc=example,dc=com",
            init_filter=lambda f: _filter_match(f, "cn", "John Doe"),
        )
        answers = await _send(msg)
        ref_lm = _create_search_result_done(
            msgid=5,
            result_code=1,
            diag="query {'op': '=', 'lhs': 'cn', "
            "'rhs': 'John Doe'} not implemented",
        )
        self._compare(answers, [ref_lm])

    async def test_with_api_down(self):
        msg = _create_search_request(
            msgid=6,
            init_filter=lambda f: _filter_user(f, username="no-api"),
            base_object="uid=no-impl,dc=example,dc=com",
        )
        answers = await _send(msg)
        ref_lm = _create_search_result_done(
            msgid=6,
            result_code=1,
            diag="api backend down (All connection attempts failed)",
        )
        self._compare(answers, [ref_lm])

    async def test_no_bind(self):
        msg = _create_search_request(
            msgid=7,
            init_filter=lambda f: _filter_user(f, username="no-impl"),
            base_object="uid=no-impl,dc=example,dc=com",
        )

        transport = MockTransport(lambda _request: Response(401))
        answers = await _send(msg, transport=transport)
        ref_lm = _create_search_result_done(
            msgid=7,
            result_code=1,
            diag="api status 401",
        )
        self._compare(answers, [ref_lm])

    async def test_user_exists(self):
        msg = _create_search_request(
            msgid=8,
            init_filter=lambda f: _filter_user(f, username="user1"),
            base_object="uid=user1,dc=example,dc=com",
        )

        transport = MockTransport(
            lambda _request: Response(
                200,
                json={
                    "username": "user1",
                    "email": "u@ser.1",
                    "display_name": "User 1",
                },
            )
        )
        answers = await _send(msg, transport=transport)
        ref_lm = _create_search_result_entry(
            msgid=8,
            dn="uid=user1,dc=example,dc=com",
            attributes={
                b"mail": b"u@ser.1",
                b"objectClass": [b"account", b"inetOrgPerson"],
                b"uid": b"user1",
                b"cn": b"User 1",
            },
        )
        self._compare(
            answers,
            [
                ref_lm,
                _create_search_result_done(msgid=8, result_code=0, diag=""),
            ],
        )
