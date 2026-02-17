from __future__ import annotations
from typing import AsyncGenerator, cast, NamedTuple

# https://lapo.it/asn1js/#MEICAQFgPQIBAwQqY249TWFuYWdlcixkYz1jc2M5NSxkYz1zZS12aS1zY2llbmNlLGRjPXJ1gAxyMDB0UGFTc3cwckQ
# https://raw.githubusercontent.com/emrig/w4156-PEAS-Oktave/76d0cce1ab4c8e529ad49dd20b50ab73ca018ce2/g/pyasn1_modules/rfc2251.py
# https://raw.githubusercontent.com/pyasn1/pyasn1-modules/02f9c577bcd0ad9fedfb0fd5dc598d323f7984bf/pyasn1_modules/rfc2251.py

import asyncio
import json
from httpx import AsyncClient
from pyasn1.type import univ, tag, namedtype, namedval, constraint
from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import EndOfStreamError, PyAsn1Error
from .ldap import parse_dn

maxInt = univ.Integer(2147483647)
api_client: AsyncClient


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


# --- Minimal ASN.1 types (very reduced) ---
class MessageID(univ.Integer):
    pass


class LDAPString(univ.OctetString):
    pass


class AttributeValue(univ.OctetString):
    pass


class AttributeDescription(LDAPString):
    pass


class LDAPDN(LDAPString):
    pass


class AttributeValues(univ.SetOf):
    componentType = AttributeValue()


class Attribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", AttributeDescription()),
        namedtype.NamedType(
            "vals", univ.SetOf(componentType=AttributeValue())
        ),
    )


class PartialAttributeList(univ.SequenceOf):
    componentType = Attribute()


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

    async def process(self, msgid: int) -> AsyncGenerator[bytes, None]:
        dn_bytes = self.getComponentByName("name").asOctets()
        dn = parse_dn(dn_bytes)
        password: bytes = (
            self.getComponentByName("authentication")
            .getComponentByName("simple")
            .asOctets()
        )
        if dn.domain_components == DOMAIN.components:
            if (
                dn.user_name is None
                and dn.common_name is not None
                and dn.common_name.lower() == b"search"
                and password == b"bindpassword"
            ):
                print("OK. BINDED search using password")
                yield encode_bind_response(
                    msgid, result=0, matchedDN=dn_bytes, diag=b""
                )
                return
            response = await api_client.post(
                "/token",
                headers={},
                data={
                    "username": dn.user_name.decode(),
                    "password": password.decode(),
                },
            )
            if response.status_code == 200:
                yield encode_bind_response(
                    msgid,
                    result=0,
                    matchedDN=dn_bytes,
                    diag=b"",
                )
                return
            print(f"ERROR: {response}")
        print(f"FAILURE {dn} `{dn_bytes}`")
        yield encode_bind_response(
            msgid,
            result=49,
            matchedDN=b"",
            diag=b"invalid credentials",
        )


class UnbindRequest(univ.Null):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 2)
    )

    async def process(self, msgid: int) -> AsyncGenerator[bytes, None]:
        print("UnbindRequest")
        return b""


# BindResponse-like result
class ResultCode(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ("success", 0), ("invalidCredentials", 49), ("operationsError", 1)
    )


class SubstringFilter(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", AttributeDescription()),
        namedtype.NamedType(
            "substrings",
            univ.SequenceOf(
                componentType=univ.Choice(
                    componentType=namedtype.NamedTypes(
                        namedtype.NamedType(
                            "initial",
                            LDAPString().subtype(
                                implicitTag=tag.Tag(
                                    tag.tagClassContext, tag.tagFormatSimple, 0
                                )
                            ),
                        ),
                        namedtype.NamedType(
                            "any",
                            LDAPString().subtype(
                                implicitTag=tag.Tag(
                                    tag.tagClassContext, tag.tagFormatSimple, 1
                                )
                            ),
                        ),
                        namedtype.NamedType(
                            "final",
                            LDAPString().subtype(
                                implicitTag=tag.Tag(
                                    tag.tagClassContext, tag.tagFormatSimple, 2
                                )
                            ),
                        ),
                    )
                )
            ),
        ),
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


class AttributeValueAssertion(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("attributeDesc", LDAPString()),
        namedtype.NamedType("assertionValue", univ.OctetString()),
    )


class MatchingRuleAssertion(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "matchingRule",
            LDAPString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 1
                )
            ),
        ),
        namedtype.OptionalNamedType(
            "type",
            AttributeDescription().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 2
                )
            ),
        ),
        namedtype.NamedType(
            "matchValue",
            univ.OctetString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 3
                )
            ),
        ),
        namedtype.DefaultedNamedType(
            "dnAttributes",
            univ.Boolean()
            .subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 4
                )
            )
            .subtype(value=0),
        ),
    )


class Referral(univ.SequenceOf):
    componentType = LDAPString()


# Ugly hack to handle recursive Filter reference (up to 3-levels deep).
# fmt: off

class Filter3(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('equalityMatch', AttributeValueAssertion().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))),
        namedtype.NamedType('substrings', SubstringFilter().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4))),
        namedtype.NamedType('greaterOrEqual', AttributeValueAssertion().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5))),
        namedtype.NamedType('lessOrEqual', AttributeValueAssertion().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 6))),
        namedtype.NamedType('present', AttributeDescription().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
        namedtype.NamedType('approxMatch', AttributeValueAssertion().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 8))),
        namedtype.NamedType('extensibleMatch', MatchingRuleAssertion().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 9)))
    )

    def build(self):
        op = self.getName()
        if op == "equalityMatch":
            return {
                "op": "=",
                "lhs": self[op]["attributeDesc"].asOctets().decode(),
                "rhs": self[op]["assertionValue"].asOctets().decode(),
            }
        if op == "present":
            return {
                "op": "has",
                "attr": self[op].asOctets().decode()
            }
        raise NotImplementedError(op)

class Filter2(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('and', univ.SetOf(componentType=Filter3()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('or', univ.SetOf(componentType=Filter3()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.NamedType('not',
                            Filter3().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
        namedtype.NamedType('equalityMatch', AttributeValueAssertion().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))),
        namedtype.NamedType('substrings', SubstringFilter().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4))),
        namedtype.NamedType('greaterOrEqual', AttributeValueAssertion().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5))),
        namedtype.NamedType('lessOrEqual', AttributeValueAssertion().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 6))),
        namedtype.NamedType('present', AttributeDescription().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
        namedtype.NamedType('approxMatch', AttributeValueAssertion().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 8))),
        namedtype.NamedType('extensibleMatch', MatchingRuleAssertion().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 9)))
    )

    def build(self):
        op = self.getName()
        if op in ("and", "or"):
            return {"op": op, "operands": [item.build() for item in self[op]]}
        elif op == "equalityMatch":
            return {
                "op": "=",
                "lhs": self[op]["attributeDesc"].asOctets().decode(),
                "rhs": self[op]["assertionValue"].asOctets().decode(),
            }
        raise NotImplementedError(op)

class Filter(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('and', univ.SetOf(componentType=Filter2()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('or', univ.SetOf(componentType=Filter2()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.NamedType('not',
                            Filter2().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
        namedtype.NamedType('equalityMatch', AttributeValueAssertion().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))),
        namedtype.NamedType('substrings', SubstringFilter().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4))),
        namedtype.NamedType('greaterOrEqual', AttributeValueAssertion().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5))),
        namedtype.NamedType('lessOrEqual', AttributeValueAssertion().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 6))),
        namedtype.NamedType('present', AttributeDescription().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
        namedtype.NamedType('approxMatch', AttributeValueAssertion().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 8))),
        namedtype.NamedType('extensibleMatch', MatchingRuleAssertion().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 9)))
    )

    build = Filter2.build

# End of Filter hack

class LDAPResult(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('resultCode', univ.Enumerated(
            namedValues=namedval.NamedValues(('success', 0), ('operationsError', 1), ('protocolError', 2),
                                             ('timeLimitExceeded', 3), ('sizeLimitExceeded', 4), ('compareFalse', 5),
                                             ('compareTrue', 6), ('authMethodNotSupported', 7),
                                             ('strongAuthRequired', 8), ('reserved-9', 9), ('referral', 10),
                                             ('adminLimitExceeded', 11), ('unavailableCriticalExtension', 12),
                                             ('confidentialityRequired', 13), ('saslBindInProgress', 14),
                                             ('noSuchAttribute', 16), ('undefinedAttributeType', 17),
                                             ('inappropriateMatching', 18), ('constraintViolation', 19),
                                             ('attributeOrValueExists', 20), ('invalidAttributeSyntax', 21),
                                             ('noSuchObject', 32), ('aliasProblem', 33), ('invalidDNSyntax', 34),
                                             ('reserved-35', 35), ('aliasDereferencingProblem', 36),
                                             ('inappropriateAuthentication', 48), ('invalidCredentials', 49),
                                             ('insufficientAccessRights', 50), ('busy', 51), ('unavailable', 52),
                                             ('unwillingToPerform', 53), ('loopDetect', 54), ('namingViolation', 64),
                                             ('objectClassViolation', 65), ('notAllowedOnNonLeaf', 66),
                                             ('notAllowedOnRDN', 67), ('entryAlreadyExists', 68),
                                             ('objectClassModsProhibited', 69), ('reserved-70', 70),
                                             ('affectsMultipleDSAs', 71), ('other', 80), ('reserved-81', 81),
                                             ('reserved-82', 82), ('reserved-83', 83), ('reserved-84', 84),
                                             ('reserved-85', 85), ('reserved-86', 86), ('reserved-87', 87),
                                             ('reserved-88', 88), ('reserved-89', 89), ('reserved-90', 90)))),
        namedtype.NamedType('matchedDN', LDAPDN()),
        namedtype.NamedType('diagnosticMessage', LDAPString()),
        namedtype.OptionalNamedType('referral', Referral().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)))
    )


# fmt: on


class SearchResultDone(LDAPResult):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 5)
    )


class SearchRequest(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 3)
    )

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("baseObject", LDAPDN()),
        namedtype.NamedType(
            "scope",
            univ.Enumerated(
                namedValues=namedval.NamedValues(
                    ("baseObject", 0), ("singleLevel", 1), ("wholeSubtree", 2)
                )
            ),
        ),
        namedtype.NamedType(
            "derefAliases",
            univ.Enumerated(
                namedValues=namedval.NamedValues(
                    ("neverDerefAliases", 0),
                    ("derefInSearching", 1),
                    ("derefFindingBaseObj", 2),
                    ("derefAlways", 3),
                )
            ),
        ),
        namedtype.NamedType(
            "sizeLimit",
            univ.Integer().subtype(
                subtypeSpec=constraint.ValueRangeConstraint(0, maxInt)
            ),
        ),
        namedtype.NamedType(
            "timeLimit",
            univ.Integer().subtype(
                subtypeSpec=constraint.ValueRangeConstraint(0, maxInt)
            ),
        ),
        namedtype.NamedType("typesOnly", univ.Boolean()),
        namedtype.NamedType("filter", Filter()),
        namedtype.NamedType("attributes", univ.SequenceOf(LDAPString())),
    )

    @staticmethod
    def _error(msgid: int, diag: str) -> bytes:
        return encode_search_result_done(
            msgid=msgid, result_code=1, matched_dn=""
        )

    async def process(self, msgid: int) -> AsyncGenerator[bytes, None]:
        dn = parse_dn(self["baseObject"].asOctets())
        print(f"SearchRequest {dn}", self["baseObject"].asOctets())
        if dn.domain_components != DOMAIN.components:
            yield self._error(
                msgid, diag=f"Invalid domain {dn.domain_components}"
            )
        if dn.organization_units == (b"users",) or dn.organization_units == ():
            async for data in self._search_users(msgid):
                yield data
        elif dn.organization_units == (b"projects",):
            async for data in self._search_projects(msgid):
                yield data
        else:
            yield self._error(
                msgid,
                diag=f"Unsupported organization units {dn.organization_units}",
            )

    async def _search_users(self, msgid: int) -> AsyncGenerator[bytes, None]:
        match self["filter"].build():
            case {
                "op": "and",
                "operands": [
                    {"lhs": "objectClass", "op": "=", "rhs": "account"},
                    {
                        "op": "or",
                        "operands": [
                            {"lhs": "uid", "op": "=", "rhs": username},
                            {"lhs": "mail", "op": "=", "rhs": username_mail},
                        ],
                    },
                ],
            } if (
                username == username_mail
            ):
                async for user in self._find_user(msgid, username):
                    yield user
            case {
                "op": "and",
                "operands": [
                    {"lhs": "objectClass", "op": "=", "rhs": "account"},
                    {
                        "op": "or",
                        "operands": [
                            {"attr": "uid", "op": "has"},
                            {"attr": "mail", "op": "has"},
                        ],
                    },
                ],
            }:
                async for user in self._list_all_users(msgid):
                    yield user
            case unknown_query:
                print(f"query {unknown_query} not implemented")

    async def _list_all_users(self, msgid: int):
        res = await api_client.get(f"/ldap/users")
        assert res.status_code == 200, (res.status_code, res)
        for user in res.json():
            username = user["username"]
            yield encode_search_result_entry(
                msgid,
                dn=f"uid={username},{DOMAIN.dc}",  # todo: escape
                attributes={
                    b"mail": [user["email"].encode()],
                    b"objectClass": [b"account", b"inetOrgPerson"],
                    b"uid": username.encode(),
                    b"cn": [user["display_name"].encode()],
                },
            )
        yield encode_search_result_done(
            msgid=msgid, result_code=0, matched_dn="", diag=""  # success
        )

    async def _find_user(self, msgid: int, username_or_email: str):
        res = await api_client.post(
            f"/ldap/find_user", json={"username_or_email": username_or_email}
        )
        user = res.json()
        assert res.status_code == 200, (res.status_code, user)
        if user is not None:
            assert "username" in user, user
            username = user["username"]
            yield encode_search_result_entry(
                msgid,
                dn=f"uid={username},{DOMAIN.dc}",  # todo: escape
                attributes={
                    b"mail": [user["email"].encode()],
                    b"objectClass": [b"account", b"inetOrgPerson"],
                    b"uid": username.encode(),
                    b"cn": [user["display_name"].encode()],
                },
            )
        yield encode_search_result_done(
            msgid=msgid, result_code=0, matched_dn="", diag=""  # success
        )

    async def _search_projects(
        self, msgid: int
    ) -> AsyncGenerator[bytes, None]:
        match self["filter"].build():
            case {"op": "=", "lhs": "memberUid", "rhs": username}:
                print(f"PROJECTS FOR {username!r}")
                res = await api_client.get(
                    f"/ldap/roles", params={"username": username}
                )
                assert res.status_code == 200, res
                for project in res.json():
                    name = project["project"]
                    yield encode_search_result_entry(
                        msgid,
                        dn=f"cn={name},{DOMAIN.dc}",  # todo: escape or remove
                        attributes={
                            b"objectClass": [b"top", b"groupOfNames"],
                            b"cn": name,
                            b"memberUid": project["members"],
                        },
                    )
            case unknown_query:
                print(f"project query {unknown_query} not implemented")
        yield encode_search_result_done(
            msgid=msgid, result_code=0, matched_dn="", diag=""  # success
        )


class SearchResultEntry(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 4)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("objectName", LDAPDN()),
        namedtype.NamedType("attributes", PartialAttributeList()),
    )


class LDAPMessage(univ.Sequence):
    componentType = namedtype.NamedTypes(
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


def encode_bind_response(msgid: int, result=0, matchedDN=b"", diag=b""):
    br = BindResponse()
    br.setComponentByName("resultCode", result)
    br.setComponentByName(
        "matchedDN",
        matchedDN.decode() if isinstance(matchedDN, bytes) else matchedDN,
    )
    br.setComponentByName(
        "diagnosticMessage", diag.decode() if isinstance(diag, bytes) else diag
    )
    lm = LDAPMessage()
    lm.setComponentByName("messageID", msgid)
    lm["protocolOp"].setComponentByName("bindResponse", br)
    return encoder.encode(lm)


def encode_search_result_entry(
    msgid: int, dn: str, attributes: dict[str, str | list[str]]
) -> bytes:
    """Encode a SearchResultEntry response"""

    # Create SearchResultEntry
    sre = SearchResultEntry()
    sre["objectName"] = dn

    # Create attributes sequence
    attrs_seq = PartialAttributeList()

    for attr_type, values in attributes.items():
        attr = Attribute()
        attr["type"] = attr_type

        # Create SetOf values
        vals_set = univ.SetOf(componentType=AttributeValue())
        for value in values if isinstance(values, list) else [values]:
            vals_set.append(value)

        attr["vals"] = vals_set
        attrs_seq.append(attr)

    sre["attributes"] = attrs_seq

    # Create LDAPMessage
    lm = LDAPMessage()
    lm.setComponentByName("messageID", msgid)
    lm["protocolOp"].setComponentByName("searchResEntry", sre)
    return encoder.encode(lm)


def encode_search_result_done(
    msgid: int, result_code=0, matched_dn="", diag=""
):
    """Encode a SearchResultDone response"""

    srd = SearchResultDone()
    srd["resultCode"] = result_code
    srd["matchedDN"] = matched_dn
    srd["diagnosticMessage"] = diag

    lm = LDAPMessage()
    lm.setComponentByName("messageID", msgid)
    lm["protocolOp"].setComponentByName("searchResDone", srd)

    return encoder.encode(lm)


# --- Connection handler ---
class LDAPProtocol:
    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        self.reader = reader
        self.writer = writer
        self.addr = writer.get_extra_info("peername")

    async def run(self):
        try:
            async for lm in self._parse_messages():
                await self._handle_message(lm)
        except asyncio.IncompleteReadError:
            pass
        finally:
            self.writer.close()
            await self.writer.wait_closed()

    async def _parse_messages(self):
        buf = b""
        while chunk := await self.reader.read(4096):
            buf += chunk
            try:
                lm, buf = cast(
                    tuple[LDAPMessage, bytes],
                    decoder.decode(buf, asn1Spec=LDAPMessage()),
                )
                yield lm
            except EndOfStreamError:
                # need more data; continue reading
                continue
            except PyAsn1Error as e:
                # unsupported package
                breakpoint()
                pass

    async def _handle_message(self, lm: LDAPMessage) -> None:
        msgid = int(lm.getComponentByName("messageID"))
        op = lm.getComponentByName("protocolOp")
        print(f"PROCESSING {type(op.getComponent())}")
        async for response in op.getComponent().process(msgid):
            self.writer.write(response)
        await self.writer.drain()


async def handle_client(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
):
    print("handle_client")
    p = LDAPProtocol(reader, writer)
    await p.run()


async def _authorize(client: AsyncClient, password: str) -> None:
    response = await client.post(
        "/token",
        data={"username": "ldap", "password": password},
    )
    if response.status_code != 200:
        raise ValueError(f"authorization failed: {response}")
    token_body = response.json()
    authorization_str = (
        f"{token_body['token_type'].capitalize()} {token_body['access_token']}"
    )
    client.headers = {"Authorization": authorization_str}


async def _server_main(
    host: str, port: int, api_url: str, password: str
) -> None:
    server = await asyncio.start_server(handle_client, host, port)
    addr = server.sockets[0].getsockname()
    base_url = api_url.rstrip("/")
    print(f"senyai_ldap server listening on {addr} and serving {DOMAIN.name}")
    print(f"with api at {base_url}")
    global api_client
    async with AsyncClient(base_url=base_url) as api_client:
        await _authorize(api_client, password)
        print("API authenticated")
        async with server:
            await server.serve_forever()


def main():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", "-p", type=int, default=10389)
    parser.add_argument("--domain", "-d", type=Domain.make, required=True)
    parser.add_argument("--api-url", "-a", default="http://127.0.0.1:8000")
    args = vars(parser.parse_args())
    with open("settings_ldap.json") as f:
        args.update(json.load(f))
    global DOMAIN
    DOMAIN = args.pop("domain")

    asyncio.run(_server_main(**args))


if __name__ == "__main__":
    main()
