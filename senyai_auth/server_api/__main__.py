from __future__ import annotations
from typing import Callable, Any
from types import CoroutineType
from argparse import ArgumentParser
import os
import base64
import asyncio
from getpass import getpass
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import sessionmaker


def _default_input(prompt: str, default: str) -> str:
    return input(f"{prompt} ({default}): ") or default


async def _init(
    async_engine: AsyncEngine, async_session: sessionmaker[AsyncSession]
):
    from .db import User, Project, Role, PermissionsAPI, Base
    from .api.user import check_password

    username = "superadmin"
    password = base64.b85encode(os.urandom(10)).decode()
    display_name = "Administrator"
    email = ""
    salt = User.make_salt()

    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as session:
        username = _default_input("Username", username)
        while True:
            password = (
                getpass(prompt=f"Strong password ({password!r}): ") or password
            )
            try:
                check_password(password, username, email, display_name)
                break
            except ValueError as e:
                password = base64.b85encode(os.urandom(10)).decode()
                print(f"weak password: {e}")
                continue
        display_name = _default_input("Display Name", display_name)
        email = _default_input("E-mail", email)
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


async def _password(
    _async_engine: AsyncEngine, async_session: sessionmaker[AsyncSession]
):
    from .db import User
    from sqlalchemy import select

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


async def _async_main(
    command: Callable[
        [AsyncEngine, sessionmaker[AsyncSession]], CoroutineType[Any, Any, Any]
    ],
):
    from . import get_settings

    settings = get_settings()
    async_engine, async_session = settings.create_engine()
    try:
        await command(async_engine, async_session)
    finally:
        print("closing connection")
        await async_engine.dispose()
        print("done")


def _main():
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(required=True)
    subparser = subparsers.add_parser(
        "init", help="Create superuser and root project"
    )
    subparser.set_defaults(command=_init)
    subparser = subparsers.add_parser("password", help="Force user password")
    subparser.set_defaults(command=_password)
    args = parser.parse_args()
    asyncio.run(_async_main(args.command))


_main()
