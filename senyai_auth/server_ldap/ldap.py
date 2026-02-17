from __future__ import annotations
from typing import NamedTuple


class DN(NamedTuple):
    user_name: bytes | None  # uid=jsmith
    common_name: bytes | None  # cn=John Smith
    organization_units: tuple[bytes, ...]
    domain_components: tuple[bytes, ...]


def parse_dn(dn: bytes) -> DN:
    parts = dn.split(b",")  # use lower to normalize dn

    common_name = user_name = None
    ou_list: list[bytes] = []
    dc_list: list[bytes] = []

    for part in parts:
        if part.startswith(b"cn="):
            common_name = part[3:]
        elif part.startswith(b"uid="):
            user_name = part[4:]
        elif part.startswith(b"ou="):
            ou_list.append(part[3:])
        elif part.startswith(b"dc="):
            dc_list.append(part[3:])

    return DN(
        user_name=user_name,
        common_name=common_name,
        organization_units=tuple(ou_list),
        domain_components=tuple(dc_list),
    )
