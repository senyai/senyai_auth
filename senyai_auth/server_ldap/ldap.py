from __future__ import annotations
from typing import NamedTuple


class DN(NamedTuple):
    user_name: bytes | None
    organization_units: tuple[bytes, ...]
    domain_components: tuple[bytes, ...]


def parse_dn(dn: bytes) -> DN:
    parts = dn.lower().split(b",")  # use lower to normalize dn

    user_name = None
    ou_list: list[bytes] = []
    dc_list: list[bytes] = []

    for part in parts:
        if part.startswith(b"cn="):
            user_name = part[3:]
        elif part.startswith(b"ou="):
            ou_list.append(part[3:])
        elif part.startswith(b"dc="):
            dc_list.append(part[3:])

    return DN(
        user_name=user_name,
        organization_units=tuple(ou_list),
        domain_components=tuple(dc_list),
    )
