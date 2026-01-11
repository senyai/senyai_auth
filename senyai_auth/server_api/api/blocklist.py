from __future__ import annotations


def not_in_blocklist(name: str) -> str:
    bad_names = (
        "admin",
        "administrator",
        "root",
        "sysadmin",
        "administrator1",
        "admin1",
        "adminroot",
        "superadmin",
        "supervisor",
        "manager",
        "owner",
        "webadmin",
        "webmaster",
        "support",
        "postmaster",
        "hostmaster",
        "ftp",
        "ftpadmin",
        "dbadmin",
        "oracle",
        "postgres",
        "sqladmin",
        "ubuntu",
        "adminuser",
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
