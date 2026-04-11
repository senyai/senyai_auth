from __future__ import annotations

from typing import Annotated
from sqlalchemy import select
from sqlalchemy.orm import load_only
from fastapi import status, Depends, APIRouter, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import (
    auth_for_project_stmt,
    Invitation,
    list_projects_stmt,
    list_roles_descriptions_stmt,
    Member,
    MemberRole,
    PermissionsAPI,
    Project,
    Role,
    select_roles_stmt,
    select_user_roles_stmt,
    User,
)
from .auth import get_current_user
from .user import UserInfo
from .invite import InvitationForm, get_invitation
from .role import RoleInfo
from ..app import get_async_session
from pydantic import BaseModel, Field
from .exceptions import (
    not_authorized_exception,
    response_description,
    response_with_perm_check,
)
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


class RoleDescription(BaseModel, strict=True):
    id: int
    name: str
    description: str


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
        for id, name, description in await session.execute(
            list_roles_descriptions_stmt, {"project_id": project_id}
        )
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
    await session.refresh(
        user, attribute_names=("contacts", "email", "display_name")
    )
    return MainModel(
        user=UserInfo.from_user(user),
        projects=[
            ProjectItem(
                id=id, name=name, display_name=display_name, parent=parent_id
            )
            for id, name, display_name, parent_id in projects
        ],
    )


@router.get(
    "/project/{project_id}/roles",
    responses={status.HTTP_401_UNAUTHORIZED: response_with_perm_check},
)
async def project_roles(
    project_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> list[RoleInfo]:
    """
    ## List roles of a project for an invitation form

    * Only manages can do it
    """

    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": user.id, "project_id": project_id},
    )
    assert permission is not None
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception

    return [
        RoleInfo.from_role(role)
        for role in await session.scalars(
            select_roles_stmt, {"project_id": project_id}
        )
    ]


@router.get(
    "/project/{project_id}/roles/{user_id}",
    responses={status.HTTP_401_UNAUTHORIZED: response_with_perm_check},
)
async def project_roles_for_user(
    project_id: int,
    user_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> list[tuple[RoleInfo, bool]]:
    """
    ## List roles of a user in a project

    * Only manages can do it
    """

    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": user.id, "project_id": project_id},
    )
    assert permission is not None
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception

    return [
        (RoleInfo.from_role(role), checked)
        for role, checked in await session.execute(
            select_user_roles_stmt,
            {"project_id": project_id, "user_id": user_id},
        )
    ]


class InvitationFormExt(InvitationForm):
    id: int
    roles: Annotated[
        list[str],
        Field(
            description="User will be added assigned these roles if possible"
        ),
    ]


class InviteInfo(BaseModel, strict=True):
    form: InvitationFormExt
    roles: Annotated[
        list[RoleDescription],
        Field(description="All roles a user can be part of"),
    ]
    project_id: Annotated[
        int, Field(description="User will be added to this project")
    ]


@router.get(
    "/invite/{id}",
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
        status.HTTP_404_NOT_FOUND: response_description(
            "Invitation not found or already accepted"
        ),
    },
)
async def project_roles_for_user(
    id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> InviteInfo:
    """
    ## For Invite update form

    * Only admins can do it
    """

    invitation = await session.scalar(
        select(Invitation).where(Invitation.id == id)
    )
    if invitation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )

    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": user.id, "project_id": invitation.project_id},
    )

    assert permission is not None
    if permission < PermissionsAPI.admin:
        raise not_authorized_exception

    form = InvitationFormExt(
        id=id,
        prompt=invitation.prompt,
        default_username=invitation.default_username,
        default_display_name=invitation.default_display_name,
        default_email=invitation.default_email,
        roles=invitation.roles,
    )

    roles = [
        RoleDescription(id=id, name=name, description=description)
        for id, name, description in await session.execute(
            list_roles_descriptions_stmt, {"project_id": invitation.project_id}
        )
    ]
    return InviteInfo(form=form, roles=roles, project_id=invitation.project_id)
