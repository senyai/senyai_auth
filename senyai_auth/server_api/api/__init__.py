"""
Tried https://github.com/fief-dev/fief, but the vibe is off
"""

from __future__ import annotations

from typing import Annotated
import os
import base64
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from pydantic import (
    AfterValidator,
    BaseModel,
    constr,
    Field,
    model_validator,
    SecretStr,
)
from fastapi import status, Depends
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from .. import app
from ..db import User, Project, Member, Role, MemberRole
from ..auth import get_current_user
from sqlalchemy.ext.asyncio import AsyncSession
from .user import router as user_router
from .project import router as project_router
from .role import router as role_router
from .. import get_async_session

app.include_router(user_router)
app.include_router(project_router)
app.include_router(role_router)


@app.get("/")
async def root(
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    """
    A way for a user to get brief information about auth status
    """
    stmt = (
        select(Project.id, Project.name)
        .join(Member)
        .where(Member.user_id == user.id)
    )
    # user2 = await session.merge(user, load=False)
    projects = (await session.execute(stmt)).scalars()
    return {"projects": projects}


@app.get("/users")
async def users(
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    users = await session.execute(select(User))
    ret = list(users.scalars())
    return ret


@app.get("/projects")
async def projects(
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    raise NotImplementedError()
    # session.add(project_db)
    # try:
    #     await session.commit()
    # except IntegrityError:
    #     raise ValueError("project already exists")
    # return project_db.id


class UserInfo(BaseModel):
    username: str
    email: str
    display_name: str
    permissions_api: list[tuple[str, str]]

    @classmethod
    def from_user(cls, user: User, permissions_api: list[tuple[str, str]]):
        return cls(
            username=user.username,
            email=user.email,
            display_name=user.display_name,
            permissions_api=permissions_api,
        )


@app.get("/whoami")
async def whoami(
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> UserInfo:
    stmt = (
        select(Project.name, Role.permissions_api)
        .join(Member)
        .join(Role)
        .where(Member.user == user)
    )
    permissions_api = await session.execute(stmt)
    return UserInfo.from_user(user, [(name, perm.name) for name, perm in permissions_api])
