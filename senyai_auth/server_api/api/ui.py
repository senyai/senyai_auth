from __future__ import annotations

from typing import Annotated
from sqlalchemy import select
from sqlalchemy.orm import load_only
from fastapi import status, Depends, APIRouter
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import (
    auth_for_project_stmt,
    list_projects_stmt,
    Member,
    MemberRole,
    PermissionsAPI,
    Project,
    Role,
    User,
)
from .auth import get_current_user
from .user import UserInfo
from .. import get_async_session
from pydantic import BaseModel
from .exceptions import not_authorized_exception, response_with_perm_check
from collections import defaultdict

router = APIRouter(tags=["ui"], prefix="/ui")


class UserItem(BaseModel, strict=True):
    id: int
    username: str
    display_name: str


class RoleItem(BaseModel, strict=True):
    id: int
    name: str
    description: str
    users: list[int]


class ProjectInfo(BaseModel, strict=True):
    display_name: str
    name: str
    members: list[UserItem]
    roles: list[RoleItem]
    permission: PermissionsAPI


@router.get(
    "/project/{project_id}",
    responses={status.HTTP_401_UNAUTHORIZED: response_with_perm_check},
)
async def project(
    project_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> ProjectInfo:
    """
    ## List users and roles of a project

    Will succeed only if user have at least "user" role
    in the project specified by `project_id`
    """
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": user.id, "project_id": project_id},
    )
    assert permission is not None
    if permission < PermissionsAPI.user:
        raise not_authorized_exception

    users_stmt = (
        select(User.id, User.username, User.display_name)
        .join(Member)
        .where(Member.project_id == project_id)
    )
    roles_stmt = select(Role.id, Role.name, Role.description).where(
        Role.project_id == project_id
    )
    role_users_stmt = (
        select(Role.id, MemberRole.user_id)
        .join(MemberRole)
        .where(Role.project_id == project_id)
    )
    roles_dict: defaultdict[int, list[int]] = defaultdict(list)
    for role_id, user_id in await session.execute(role_users_stmt):
        roles_dict[role_id].append(user_id)

    project = await session.get_one(
        Project,
        project_id,
        options=[load_only(Project.name, Project.display_name)],
    )

    member = [
        UserItem(id=id, username=username, display_name=display_name)
        for id, username, display_name in await session.execute(users_stmt)
    ]
    roles = [
        RoleItem(
            id=id, name=name, description=description, users=roles_dict[id]
        )
        for id, name, description in await session.execute(roles_stmt)
    ]
    return ProjectInfo(
        display_name=project.display_name,
        name=project.name,
        members=member,
        roles=roles,
        permission=permission,
    )


class ProjectItem(BaseModel, strict=True):
    id: int
    name: str
    display_name: str
    parent: int | None


class MainModel(BaseModel, strict=True):
    user: UserInfo
    projects: list[ProjectItem]


@router.get(
    "/main", responses={status.HTTP_401_UNAUTHORIZED: response_with_perm_check}
)
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
