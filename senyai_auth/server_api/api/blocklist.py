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

    if name in bad_names or name.startswith("admin") or name.endswith("admin"):
        raise ValueError("is blocked because it is suspicious")
    return name
