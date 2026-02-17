from __future__ import annotations


def not_in_blocklist(name: str) -> str:
    bad_names = (
        "admin",
        "admin1",
        "administrator",
        "administrator1",
        "adminroot",
        "adminuser",
        "dbadmin",
        "devel",
        "ftp",
        "ftpadmin",
        "hostmaster",
        "ldap",
        "manager",
        "oracle",
        "owner",
        "postgres",
        "postmaster",
        "root",
        "sqladmin",
        "superadmin",
        "supervisor",
        "support",
        "sysadmin",
        "ubuntu",
        "webadmin",
        "webmaster",
    )
    count_digits = sum(ch.isdigit() for ch in name)
    if (len(name) - count_digits) < count_digits:
        raise ValueError(
            "more than half of username characters can't be digits"
        )
    if name in bad_names or name.startswith("admin") or name.endswith("admin"):
        if name != "adminov":
            raise ValueError("is blocked because it is suspicious")
    return name
