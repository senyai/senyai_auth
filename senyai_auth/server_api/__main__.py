from argparse import ArgumentParser
import os
import base64
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
import asyncio
from getpass import getpass


def default_input(prompt: str, default: str) -> str:
    return input(f"{prompt} ({default}): ") or default


async def init():
    from . import get_settings
    from .db import User, Project, Role, PermissionsAPI, Base
    from .api.user import check_password

    settings = get_settings()
    async_engine, async_session = settings.create_engine()
    username = "superadmin"
    password = base64.b85encode(os.urandom(10)).decode()
    display_name = "Administrator"
    email = ""
    salt = base64.b85encode(os.urandom(16)).decode()

    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as session:
        while True:
            username = default_input("Username", username)
            display_name = default_input("Display Name", display_name)
            email = default_input("E-mail", email)
            password = (
                getpass(prompt=f"Strong password ({password!r}): ") or password
            )
            try:
                check_password(password, username, email, display_name)
                break
            except ValueError as e:
                print(f"weak password: {e}")
                continue
        user = User(
            username=username,
            display_name=display_name,
            password_hash=User.create_password_hash(password, salt),
            salt=salt,
            email=email,
        )
        session.add(user)
        project = Project(
            name="root",
            display_name="Root project",
            description="Special project for superadmin",
        )
        session.add(project)
        project.members.append(user)
        role = Role(
            name="Admin",
            project=project,
            description="Special role for superusers",
            permissions_api=PermissionsAPI.superadmin,
        )
        role.members.append(user)
        session.add(role)
        await session.commit()
    print("stop")


async def password():
    from . import get_settings
    from .db import User
    from sqlalchemy import select

    settings = get_settings()
    _async_engine, async_session = settings.create_engine()
    async with async_session() as session:
        while True:
            username = input("Username: ")
            user = await session.scalar(
                select(User).where(User.username == username)
            )
            if user is None:
                print(f"user {username} does not exist")
                continue
            password = getpass(prompt=f"New strong password: ")
            user.update_password(password)
            session.add(user)
            await session.commit()
            break


def main():
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(required=True)
    subparser = subparsers.add_parser(
        "init", help="Create superuser and root project"
    )
    subparser.set_defaults(func=init)
    subparser = subparsers.add_parser("password", help="Force user password")
    subparser.set_defaults(func=password)
    args = parser.parse_args()
    asyncio.run(args.func())


main()
