"""
Tried https://github.com/fief-dev/fief, but the vibe is off
"""

from __future__ import annotations

from typing import Annotated
from sqlalchemy import select
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from .. import app
from ..db import User, Project, Member
from .auth import get_current_user
from .user import router as user_router
from .project import router as project_router
from .role import router as role_router
from .invite import router as invite_router
from .ui import router as ui_router
from .. import get_async_session

app.include_router(user_router)
app.include_router(project_router)
app.include_router(role_router)
app.include_router(invite_router)
app.include_router(ui_router)


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
