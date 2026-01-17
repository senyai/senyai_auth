"""
Tried https://github.com/fief-dev/fief, but the vibe is off
"""

from __future__ import annotations

from typing import Annotated
from sqlalchemy import select
from pydantic import BaseModel
from fastapi import Depends
from .. import app
from ..db import User, Project, Member, Role
from ..auth import get_current_user
from sqlalchemy.ext.asyncio import AsyncSession
from .user import router as user_router
from .project import router as project_router
from .role import router as role_router
from .invite import router as invite_router
from .. import get_async_session

app.include_router(user_router)
app.include_router(project_router)
app.include_router(role_router)
app.include_router(invite_router)


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
    """
    ## List projects user belong to
    """
    projects = await session.scalars(
        select(Project).where(Project.members.contains(user))
    )
    return [{"id": project.id, "name": project.name} for project in projects]
