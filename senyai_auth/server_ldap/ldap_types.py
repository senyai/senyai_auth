from __future__ import annotations
from pyasn1.type import univ


class LDAPString(univ.OctetString):
    pass


class LDAPMessage(univ.Sequence):
    # initialized in __init__.py
    pass
