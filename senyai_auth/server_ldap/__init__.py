from __future__ import annotations
from typing import AsyncGenerator, cast

# https://lapo.it/asn1js/#MEICAQFgPQIBAwQqY249TWFuYWdlcixkYz1jc2M5NSxkYz1zZS12aS1zY2llbmNlLGRjPXJ1gAxyMDB0UGFTc3cwckQ
# https://raw.githubusercontent.com/emrig/w4156-PEAS-Oktave/76d0cce1ab4c8e529ad49dd20b50ab73ca018ce2/g/pyasn1_modules/rfc2251.py
# https://raw.githubusercontent.com/pyasn1/pyasn1-modules/02f9c577bcd0ad9fedfb0fd5dc598d323f7984bf/pyasn1_modules/rfc2251.py

import asyncio
from pyasn1.type import univ, tag, namedtype, namedval, constraint
from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import EndOfStreamError, PyAsn1Error
from .ldap import parse_dn

maxInt = univ.Integer(2147483647)


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
        dn = parse_dn(self.getComponentByName("name").asOctets())
        password: bytes = (
            self.getComponentByName("authentication")
            .getComponentByName("simple")
            .asOctets()
        )
        if dn.domain_components == (b"csc95", b"se-vi-science", b"ru"):
            if dn.user_name == b"manager" and password == b"r00tPaSsw0rD":
                print("SUCCESS for manager")
                yield encode_bind_response(
                    msgid,
                    result=0,
                    matchedDN=self.getComponentByName("name").asOctets(),
                    diag=b"",
                )
                return
            elif (
                dn.user_name is None
                and dn.common_name.lower() == b"search"
                and password == b"bindpassword"
            ):
                print("SUCCESS for search")
                yield encode_bind_response(
                    msgid, result=0, matchedDN=b"", diag=b""
                )
                return
        print("FAILURE", self.getComponentByName("name").asOctets())
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
            msgid=msgid, result_code=1, matched_dn="", diag="Invalid domain"
        )

    async def process(self, msgid: int) -> AsyncGenerator[bytes, None]:
        dn = parse_dn(self["baseObject"].asOctets())
        if dn.domain_components != (b"csc95", b"se-vi-science", b"ru"):
            print("INVALID DOMAIN", dn.domain_components)
            yield self._error(msgid, diag="Invalid domain")
        if dn.organization_units == (b"users",):
            async for data in self._process_users(msgid):
                yield data
        elif dn.organization_units == (b"projects",):
            async for data in self._process_projects(msgid):
                yield data
        else:
            yield self._error(msgid, diag="Unsupported organization units")

    async def _process_users(self, msgid: int) -> AsyncGenerator[bytes, None]:
        if (
            self["filter"]["and"][0]["equalityMatch"][
                "attributeDesc"
            ].asOctets()
            != b"objectClass"
        ):
            yield self._error(msgid, diag="Unsupported request")
            return
        if (
            self["filter"]["and"][0]["equalityMatch"][
                "assertionValue"
            ].asOctets()
            != b"account"
        ):
            yield self._error(msgid, diag="Unsupported request")
            return

        yield encode_search_result_entry(
            msgid,
            dn="ou=users,dc=csc95.dc=se-vi-science,dc=ru",
            attributes={
                b"mail": [b"manager@example.com"],
                b"objectClass": [b"account", b"inetOrgPerson"],
                b"uid": [b"manager"],
                b"cn": ["Тестовый Пользователь 1".encode()],
            },
        )
        yield encode_search_result_done(
            msgid=msgid, result_code=0, matched_dn="", diag=""  # success
        )

    async def _process_projects(self, msgid: int) -> AsyncGenerator[bytes, None]:
        raise NotImplementedError("aaaa")


class SearchResultEntry(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 4)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("objectName", LDAPDN()),
        namedtype.NamedType("attributes", PartialAttributeList()),
    )


class LDAPOID(univ.OctetString):
    pass


class Control(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("controlType", LDAPOID()),
        namedtype.DefaultedNamedType("criticality", univ.Boolean("False")),
        namedtype.OptionalNamedType("controlValue", univ.OctetString()),
    )


class Controls(univ.SequenceOf):
    componentType = Control()


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
        namedtype.OptionalNamedType(
            "controls",
            univ.Any(),
            # Controls().subtype(
            #     implicitTag=tag.Tag(
            #         tag.tagClassContext, tag.tagFormatConstructed, 0
            #     )
            # ),
        ),
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


# from pyasn1 import debug

# debug.setLogger(debug.Debug("all"))


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
        async for response in op.getComponent().process(msgid):
            self.writer.write(response)
        await self.writer.drain()


async def handle_client(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
):
    print("handle_client")
    p = LDAPProtocol(reader, writer)
    await p.run()


async def server_main(host: str, port: int) -> None:
    server = await asyncio.start_server(handle_client, host, port)
    addr = server.sockets[0].getsockname()
    print(f"senyai_ldap server listening on {addr}")
    async with server:
        await server.serve_forever()


def main():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", "-p", type=int, default=10389)
    args = parser.parse_args()

    asyncio.run(server_main(**vars(args)))


if __name__ == "__main__":
    main()
