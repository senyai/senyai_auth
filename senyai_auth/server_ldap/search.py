from __future__ import annotations
from typing import AsyncGenerator
from pyasn1.type import univ, tag, namedtype, namedval, constraint
from httpx2 import AsyncClient, ConnectError
from .ldap_types import LDAPString
from .ldap import parse_dn, DN
from .logger import create_logger
from .ldap_types import LDAPMessage
from .. import server_ldap

logger = create_logger(__name__)
maxInt = univ.Integer(2147483647)


class AttributeValueAssertion(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("attributeDesc", LDAPString()),
        namedtype.NamedType("assertionValue", univ.OctetString()),
    )


class AttributeDescription(LDAPString):
    pass


class LDAPDN(LDAPString):
    pass


class Referral(univ.SequenceOf):
    componentType = LDAPString()


class AttributeValue(univ.OctetString):
    pass


class AttributeDescriptionList(univ.SequenceOf):
    componentType = AttributeDescription()


class Attribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", AttributeDescription()),
        namedtype.NamedType(
            "vals", univ.SetOf(componentType=AttributeValue())
        ),
    )


class PartialAttributeList(univ.SequenceOf):
    componentType = Attribute()


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
        namedtype.NamedType("attributes", AttributeDescriptionList()),
    )

    @staticmethod
    def _error(diag: str) -> LDAPMessage:
        return _create_search_result_done(result_code=1, diag=diag)

    async def process(
        self, api_client: AsyncClient
    ) -> AsyncGenerator[LDAPMessage, None]:
        dn = parse_dn(self["baseObject"].asOctets())
        logger.info(f"SearchRequest {dn} {self["baseObject"].asOctets()}")
        try:
            if dn.domain_components != server_ldap.DOMAIN.components:
                yield self._error(
                    diag=f"Invalid domain {dn.domain_components}"
                )
            elif (
                dn.organization_units == (b"users",)
                or dn.organization_units == ()
            ):
                async for data in self._search_users(api_client, dn):
                    yield data
            elif dn.organization_units == (b"projects",):
                async for data in self._search_projects(api_client):
                    yield data
            else:
                yield self._error(
                    diag=f"Unsupported organization units {dn.organization_units}",
                )
        except ConnectError as e:
            yield self._error(
                diag=f"api backend down ({e})",
            )

    async def _search_users(
        self, api_client: AsyncClient, dn: DN
    ) -> AsyncGenerator[LDAPMessage, None]:
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
                async for lm in self._find_user(api_client, username):
                    yield lm
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
                async for lm in self._list_all_users(api_client):
                    yield lm
            case {"op": "=", "lhs": "memberOf", "rhs": rhs_dn_str}:
                rhs_dn = parse_dn(rhs_dn_str.encode())
                assert rhs_dn.common_name == b"admin", rhs_dn.common_name
                assert rhs_dn.organization_units == (b"groups",)
                assert dn.user_name is not None, "client problem"
                async for lm in self._find_user(
                    api_client, dn.user_name.decode(), only_admin=True
                ):
                    yield lm
            case unknown_query:
                msg = f"query {unknown_query} not implemented"
                logger.warning(msg)
                yield self._error(msg)

    async def _list_all_users(self, api_client: AsyncClient):
        res = await api_client.get(f"/ldap/users/git")
        assert res.status_code == 200, (res.status_code, res)
        for user in res.json():
            username = user["username"]
            yield _create_search_result_entry(
                dn=f"uid={username},{server_ldap.DOMAIN.dc}",  # todo: escape
                attributes={
                    b"mail": [user["email"].encode()],
                    b"objectClass": [b"account", b"inetOrgPerson"],
                    b"uid": username.encode(),
                    b"cn": [user["display_name"].encode()],
                    b"memberOf": [
                        f"cn={group},ou=groups,{server_ldap.DOMAIN.dc}".encode()
                        for group in user["permissions"]
                    ],
                },
            )
        yield _create_search_result_done()  # success

    async def _find_user(
        self,
        api_client: AsyncClient,
        username_or_email: str,
        only_admin: bool = False,
    ):
        res = await api_client.get(
            f"/ldap/find_user/git",
            params={"username_or_email": username_or_email},
        )
        if res.status_code == 200:
            user = res.json()
            assert res.status_code == 200, (res.status_code, user)
            assert "username" in user, user
            username = user["username"]
            if not only_admin or "admin" in user["permissions"]:
                yield _create_search_result_entry(
                    dn=f"uid={username},{server_ldap.DOMAIN.dc}",  # todo: escape
                    attributes={
                        b"mail": [user["email"].encode()],
                        b"objectClass": [b"account", b"inetOrgPerson"],
                        b"uid": username.encode(),
                        b"cn": [user["display_name"].encode()],
                    },
                )
        else:
            yield _create_search_result_done(
                result_code=1, diag=f"api status {res.status_code}"
            )
            return
        yield _create_search_result_done()  # success

    async def _search_projects(
        self, api_client: AsyncClient
    ) -> AsyncGenerator[LDAPMessage, None]:
        match self["filter"].build():
            case {"op": "=", "lhs": "memberUid", "rhs": username}:
                logger.info(f"PROJECTS FOR {username!r}")
                res = await api_client.get(
                    f"/ldap/roles/git",
                    params={"username": username},
                )
                assert res.status_code == 200, res
                for name in res.json():  # list os strings
                    yield _create_search_result_entry(
                        dn=f"cn={name},{server_ldap.DOMAIN.dc}",  # todo: escape or remove
                        attributes={
                            b"objectClass": [b"top", b"groupOfNames"],
                            b"cn": name,
                            b"memberUid": [username],
                        },
                    )
            case unknown_query:
                logger.info(f"project query {unknown_query} not implemented")
        yield _create_search_result_done()  # success


class SearchResultEntry(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 4)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("objectName", LDAPDN()),
        namedtype.NamedType("attributes", PartialAttributeList()),
    )


def _create_search_result_done(
    result_code: int = 0,
    matched_dn: bytes = b"",
    diag: str = "",
) -> LDAPMessage:
    srd = SearchResultDone()
    srd["resultCode"] = result_code
    srd["matchedDN"] = matched_dn
    srd["diagnosticMessage"] = diag

    ldap_message = LDAPMessage()
    ldap_message["protocolOp"].setComponentByName("searchResDone", srd)
    return ldap_message


def _create_search_result_entry(
    dn: str, attributes: dict[bytes, bytes | list[bytes]]
) -> LDAPMessage:
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

    ldap_message = LDAPMessage()
    ldap_message["protocolOp"].setComponentByName("searchResEntry", sre)
    return ldap_message
