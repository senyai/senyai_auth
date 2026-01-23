from __future__ import annotations

from typing import Annotated
from sqlalchemy import select
from fastapi import Depends, APIRouter
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import User, list_projects_stmt
from .auth import get_current_user
from .user import UserInfo
from .. import get_async_session
from pydantic import BaseModel


router = APIRouter(tags=["ui"], prefix="/ui")


class UserItem(BaseModel, strict=True):
    id: int
    display_name: str


@router.get("/users/{project_id}")
async def users(
    project_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    """
    ## List users that can be used int a project
    """
    # for now return all users because the exact rules are unclear
    users = await session.execute(select(User.id, User.display_name))
    ret = [
        UserItem(id=id, display_name=display_name)
        for id, display_name in users
    ]
    return ret


class ProjectItem(BaseModel, strict=True):
    id: int
    name: str
    parent: int | None


class MainModel(BaseModel, strict=True):
    user: UserInfo
    projects: list[ProjectItem]


@router.get("/main", tags=["ui"])
async def projects(
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> MainModel:
    """
    ## Main page for authorized user

    * User info
    * List of projects
    """
    projects = await session.execute(list_projects_stmt, {"user_id": user.id})
    user = await session.merge(user)
    await session.refresh(user, attribute_names=("contacts",))
    return MainModel(
        user=UserInfo.from_user(user),
        projects=[
            ProjectItem(id=id, name=name, parent=parent_id)
            for id, name, parent_id in projects
        ],
    )
