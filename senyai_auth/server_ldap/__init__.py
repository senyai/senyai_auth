from __future__ import annotations
from typing import cast

# https://lapo.it/asn1js/#MEICAQFgPQIBAwQqY249TWFuYWdlcixkYz1jc2M5NSxkYz1zZS12aS1zY2llbmNlLGRjPXJ1gAxyMDB0UGFTc3cwckQ
# https://raw.githubusercontent.com/emrig/w4156-PEAS-Oktave/76d0cce1ab4c8e529ad49dd20b50ab73ca018ce2/g/pyasn1_modules/rfc2251.py

import asyncio
from pyasn1.type import univ, tag, namedtype, char, namedval, constraint
from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import EndOfStreamError
from .ldap import parse_dn

# BASE_DN = b"dc=csc95,dc=se-vi-science,dc=ru"
# USERS_OU = b"ou=users," + BASE_DN

# # In-memory directory: DN (bytes) -> {attr (bytes): [value bytes]}
# ENTRIES = {}
# for i in range(1, 11):
#     uid = f"user{i}".encode()
#     dn = b"uid=" + uid + b"," + USERS_OU
#     ENTRIES[dn] = {
#         b"objectClass": [b"inetOrgPerson", b"person", b"top"],
#         b"uid": [uid],
#         b"cn": [uid],
#         b"sn": [f"User{i}".encode()],
#         b"userPassword": [f"pass{i}".encode()],
#     }
# ENTRIES[BASE_DN] = {b"objectClass": [b"domain", b"top"], b"dc": [b"example"]}
# ENTRIES[USERS_OU] = {
#     b"objectClass": [b"organizationalUnit", b"top"],
#     b"ou": [b"users"],
# }


# --- Minimal ASN.1 types (very reduced) ---
class MessageID(univ.Integer):
    pass


class LDAPString(char.GeneralString):
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
        namedtype.NamedType("attrType", AttributeDescription()),
        namedtype.NamedType("attrVals", AttributeValues()),
    )


class PartialAttributeList(univ.SequenceOf):
    componentType = Attribute()


# Extremely simplified BindRequest [APPLICATION 0] encoded as a Sequence here
# class BindRequest(univ.Sequence):
#     # tagSet = univ.Sequence.tagSet.tagImplicitly(
#     #     tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0)
#     # )

#     componentType = namedtype.NamedTypes(
#         namedtype.NamedType("version", univ.Integer()),
#         namedtype.NamedType("name", LDAPString()),
#         # simple auth tagged [0], we treat it as OCTET STRING
#         namedtype.NamedType(
#             "auth",
#             univ.OctetString().subtype(
#                 implicitTag=tag.Tag(
#                     tag.tagClassContext, tag.tagFormatSimple, 0
#                 )
#             ),
#         ),
#     )


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

    def process(self, msgid: int) -> bytes:
        dn = parse_dn(self.getComponentByName("name").asOctets())
        password: bytes = (
            self.getComponentByName("authentication")
            .getComponentByName("simple")
            .asOctets()
        )
        if (
            dn.user_name == b"manager"
            and dn.domain_components == (b"csc95", b"se-vi-science", b"ru")
            and password == b"r00tPaSsw0rD"
        ):
            return encode_bind_response(
                msgid, result=0, matchedDN=matched, diag=b""
            )
        else:
            return encode_bind_response(
                msgid,
                result=49,
                matchedDN=b"",
                diag=b"invalid credentials",
            )


# BindResponse-like result
class ResultCode(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ("success", 0), ("invalidCredentials", 49), ("operationsError", 1)
    )


class BindResponse(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("resultCode", ResultCode()),
        namedtype.NamedType("matchedDN", LDAPString()),
        namedtype.NamedType("diagnosticMessage", LDAPString()),
    )


# Simplified SearchRequest: baseObject, scope, filter (raw string), attributes (sequence of strings)
class SearchRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("baseObject", LDAPString()),
        namedtype.NamedType("scope", univ.Integer()),
        namedtype.NamedType("filter", LDAPString()),
        namedtype.NamedType(
            "attributes", univ.SequenceOf(componentType=LDAPString())
        ),
    )


class SearchResultEntry(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("objectName", LDAPString()),
        namedtype.NamedType("attributes", PartialAttributeList()),
    )


# LDAPMessage wrapper: messageID + protocolOp bytes (we use OCTET STRING to carry the encoded choice)
# class LDAPMessage(univ.Sequence):
#     componentType = namedtype.NamedTypes(
#         namedtype.NamedType('messageID', MessageID()),
#         namedtype.NamedType('protocolOp', univ.OctetString())
#     )


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
                    # namedtype.NamedType("bindResponse", BindResponse()),
                    # namedtype.NamedType('unbindRequest', UnbindRequest()),
                    # namedtype.NamedType("searchRequest", SearchRequest()),
                    # namedtype.NamedType("searchResEntry", SearchResultEntry()),
                    # namedtype.NamedType('searchResDone', SearchResultDone()),
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


# --- Helpers ---
def parse_simple_filter(filt_str: str):
    # accept "(attr=value)" only
    if filt_str.startswith("(") and filt_str.endswith(")") and "=" in filt_str:
        k, v = filt_str[1:-1].split("=", 1)
        return k.encode(), v.encode()
    return None, None


def search_entries(base: bytes, scope: int, filt: str):
    k, v = parse_simple_filter(filt)
    results = []
    for dn, attrs in ENTRIES.items():
        # scope: 2=subtree,1=onelevel,0=base
        if scope == 0:
            if dn != base:
                continue
        elif scope == 1:
            parent = b",".join(dn.split(b",")[1:]) if b"," in dn else b""
            if parent != base:
                continue
        else:  # subtree
            if not dn.endswith(base):
                continue
        if k is None:
            continue
        if k in attrs and any(val == v for val in attrs[k]):
            results.append((dn, attrs))
    return results


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
    proto = encoder.encode(br)
    lm = LDAPMessage()
    lm.setComponentByName("messageID", msgid)
    lm.setComponentByName("protocolOp", proto)
    return encoder.encode(lm)


def encode_search_entry(msgid: int, dn: bytes, attrs: dict):
    entry = SearchResultEntry()
    entry.setComponentByName("objectName", dn.decode())
    pal = []
    for atype, values in attrs.items():
        a = Attribute()
        a.setComponentByName("attrType", atype.decode())
        avs = AttributeValues()
        for v in values:
            avs.setComponentByPosition(len(avs), v)
        a.setComponentByName("attrVals", avs)
        pal.append(a)
    entry.setComponentByName("attributes", pal)
    lm = LDAPMessage()
    lm.setComponentByName("messageID", msgid)
    lm.setComponentByName("protocolOp", encoder.encode(entry))
    return encoder.encode(lm)


def encode_search_done(msgid: int):
    return encode_bind_response(msgid, result=0, matchedDN=b"", diag=b"")


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

    async def _handle_message(self, lm: LDAPMessage) -> None:
        print("_handle_message")
        msgid = int(lm.getComponentByName("messageID"))
        op = lm.getComponentByName("protocolOp")
        response = op.getComponent().process(msgid)
        self.writer.write(response)
        await self.writer.drain()

        #     lm, _ = decoder.decode(raw_msg_bytes, asn1Spec=LDAPMessage())

        # try:
        #     lm, _ = decoder.decode(raw_msg_bytes, asn1Spec=LDAPMessage())
        #     msgid = int(lm.getComponentByName("messageID"))
        #     proto_raw = bytes(lm.getComponentByName("protocolOp"))
        #     # Try BindRequest decode
        #     try:
        #         br, _ = decoder.decode(proto_raw, asn1Spec=BindRequest())
        #         name = br.getComponentByName("name").asOctets()
        #         password = br.getComponentByName("auth").asOctets()
        #         # Find matching entry by full DN or uid
        #         matched = None
        #         for dn, attrs in ENTRIES.items():
        #             if dn == name or (
        #                 attrs.get(b"uid") and attrs[b"uid"][0] == name
        #             ):
        #                 if attrs.get(b"userPassword", [b""])[0] == password:
        #                     matched = dn
        #                     break
        #         if matched:
        #             resp = encode_bind_response(
        #                 msgid, result=0, matchedDN=matched, diag=b""
        #             )
        #         else:
        #             resp = encode_bind_response(
        #                 msgid,
        #                 result=49,
        #                 matchedDN=b"",
        #                 diag=b"invalid credentials",
        #             )
        #         self.writer.write(resp)
        #         await self.writer.drain()
        #         return
        #     except Exception:
        #         print("EXCEPTION A")
        #         breakpoint()
        #         pass

        #     # Try SearchRequest
        #     try:
        #         sr, _ = decoder.decode(proto_raw, asn1Spec=SearchRequest())
        #         base = sr.getComponentByName("baseObject").asOctets()
        #         scope = int(sr.getComponentByName("scope"))
        #         filt = str(sr.getComponentByName("filter"))
        #         # attributes list ignored in this minimal impl
        #         results = search_entries(base, scope, filt)
        #         for dn, attrs in results:
        #             self.writer.write(encode_search_entry(msgid, dn, attrs))
        #             await self.writer.drain()
        #         self.writer.write(encode_search_done(msgid))
        #         await self.writer.drain()
        #         return
        #     except Exception:
        #         print("EXCEPTION B")
        #         breakpoint()

        #     # Unknown operation
        #     self.writer.write(
        #         encode_bind_response(
        #             msgid, result=1, matchedDN=b"", diag=b"unsupported"
        #         )
        #     )
        #     await self.writer.drain()
        # except Exception:
        #     print("EXCEPTION C")
        #     breakpoint()
        #     # ignore parse errors
        #     return


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
