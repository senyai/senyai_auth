from __future__ import annotations

from typing import Annotated
from sqlalchemy import select
from fastapi import Depends, APIRouter
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import (
    auth_for_project_stmt,
    list_projects_stmt,
    Member,
    PermissionsAPI,
    Role,
    User,
)
from .auth import get_current_user
from .user import UserInfo
from .. import get_async_session
from pydantic import BaseModel
from .exceptions import not_authorized_exception


router = APIRouter(tags=["ui"], prefix="/ui")


class UserItem(BaseModel, strict=True):
    id: int
    username: str
    display_name: str


class RoleItem(BaseModel, strict=True):
    id: int
    name: str


class ProjectInfo(BaseModel, strict=True):
    members: list[UserItem]
    roles: list[RoleItem]


@router.get("/project/{project_id}")
async def project(
    project_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    """
    ## List users and roles of a project

    Ensures that user has "user" role in the project specified by `project_id`
    """
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": user.id, "project_id": project_id},
    )
    if permission < PermissionsAPI.user:
        raise not_authorized_exception

    users_stmt = (
        select(User.id, User.username, User.display_name)
        .join(Member)
        .where(Member.project_id == project_id)
    )
    roles_stmt = select(Role.id, Role.name).where(
        Role.project_id == project_id
    )

    member = [
        UserItem(id=id, username=username, display_name=display_name)
        for id, username, display_name in await session.execute(users_stmt)
    ]
    roles = [
        RoleItem(id=id, name=name)
        for id, name in await session.execute(roles_stmt)
    ]
    return ProjectInfo(
        members=member,
        roles=roles,
    )


class ProjectItem(BaseModel, strict=True):
    id: int
    name: str
    display_name: str
    parent: int | None


class MainModel(BaseModel, strict=True):
    user: UserInfo
    projects: list[ProjectItem]


@router.get("/main")
async def projects(
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> MainModel:
    """
    ## Main page for ANY authorized user

    * User info
    * List of projects
    """
    projects = await session.execute(list_projects_stmt, {"user_id": user.id})
    user = await session.merge(user)
    await session.refresh(user, attribute_names=("contacts",))
    return MainModel(
        user=UserInfo.from_user(user),
        projects=[
            ProjectItem(
                id=id, name=name, display_name=display_name, parent=parent_id
            )
            for id, name, display_name, parent_id in projects
        ],
    )
