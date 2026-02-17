from __future__ import annotations
from typing import Annotated
from pydantic import BaseModel, StringConstraints
from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import (
    permissions_api_stmt,
    PermissionsAPI,
    Project,
    Role,
    MemberRole,
    User,
)
from .auth import get_current_user
from .. import get_async_session
from .exceptions import (
    not_authorized_exception,
    response_with_perm_check,
)

router = APIRouter(prefix="/ldap", tags=["ldap"])


class FindUser(BaseModel, strict=True, frozen=True):
    username_or_email: Annotated[
        str, StringConstraints(min_length=1, max_length=32)
    ]


class LDAPUser(BaseModel, strict=True, frozen=True):
    username: str
    display_name: str
    email: str


@router.post(
    "/find_user",
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
    },
)
async def find_user(
    find_user: FindUser,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> LDAPUser | None:
    """
    ## Find user for LDAP server

    * Only admins can do this action
    """
    permissions = await session.scalar(
        permissions_api_stmt, {"user_id": auth_user.id}
    )
    if not permissions & PermissionsAPI.admin:
        raise not_authorized_exception

    for username, display_name, email in await session.execute(
        select(User.username, User.display_name, User.email).where(
            (User.username == find_user.username_or_email)
            | (User.email == find_user.username_or_email)
        )
        # technically, multiple users can have the same email,
        # but are discouraged to do so
        .limit(1)
    ):
        return LDAPUser(
            username=username, display_name=display_name, email=email
        )


@router.get(
    "/users",
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
    },
)
async def all_users(
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> list[LDAPUser]:
    """
    ## List all enabled users for LDAP server

    * Only admins can do this action
    """
    permissions = await session.scalar(
        permissions_api_stmt, {"user_id": auth_user.id}
    )
    if not permissions & PermissionsAPI.admin:
        raise not_authorized_exception

    return [
        LDAPUser(username=username, display_name=display_name, email=email)
        for username, display_name, email in await session.execute(
            select(User.username, User.display_name, User.email)
        )
    ]


class LDAPProject(BaseModel, strict=True, frozen=True):
    project: str  # project-role format
    members: list[str]


@router.get(
    "/roles",
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
    },
)
async def user_roles(
    username: str,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> list[LDAPProject]:
    """
    ## List all enabled users for LDAP server

    * Only admins can do this action
    """
    permissions = await session.scalar(
        permissions_api_stmt, {"user_id": auth_user.id}
    )
    if not permissions & PermissionsAPI.admin:
        raise not_authorized_exception

    # this statement is crazy. debug then we have more info on what LDAP needs
    return [
        LDAPProject(project=f"{role_name}-{project_name}", members=[username])
        for role_name, project_name, username in await session.execute(
            select(Role.name, Project.name, User.username)
            .join(Project)
            .join(MemberRole)
            .join(User)
            .where(User.username == username)
        )
    ]
