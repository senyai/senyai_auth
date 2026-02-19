from __future__ import annotations
from typing import Annotated, Literal
from pydantic import BaseModel, StringConstraints
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import (
    permissions_api_stmt,
    get_user_by_username_or_email_stmt,
    permissions_extra_stmt,
    permissions_git_stmt,
    permissions_storage_stmt,
    all_users_extra_stmt,
    all_users_storage_stmt,
    all_users_git_stmt,
    select_userid_by_username_stmt,
    PermissionsAPI,
    User,
)
from .auth import get_current_user
from .. import get_async_session
from .exceptions import (
    not_authorized_exception,
    response_description,
    response_with_perm_check,
)

router = APIRouter(prefix="/ldap", tags=["ldap"])
Domain = Literal["git", "storage", "extra"]


def _permissions_from_str(permissions: str | None) -> list[str]:
    if permissions:
        return sorted(set(permissions.split("|")))
    return []


class LDAPUser(BaseModel, strict=True, frozen=True):
    username: str
    display_name: str
    email: str
    permissions: list[str]


@router.get(
    "/find_user/{domain}",
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
        status.HTTP_404_NOT_FOUND: response_description("User not found"),
    },
)
async def find_user(
    username_or_email: Annotated[
        str, StringConstraints(min_length=1, max_length=32)
    ],
    domain: Domain,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> LDAPUser:
    """
    ## Find user for LDAP server

    * Return user that has git permissions assigned
    * Only admins can do this action
    """
    permissions = await session.scalar(
        permissions_api_stmt, {"user_id": auth_user.id}
    )
    if permissions < PermissionsAPI.admin:
        raise not_authorized_exception

    user = await session.scalar(
        get_user_by_username_or_email_stmt,
        {"username_or_email": username_or_email},
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    permissions_stmt = {
        "extra": permissions_extra_stmt,
        "git": permissions_git_stmt,
        "storage": permissions_storage_stmt,
    }[domain]
    permissions_str = await session.scalar(
        permissions_stmt, {"user_id": user.id}
    )
    return LDAPUser(
        username=user.username,
        display_name=user.display_name,
        email=user.email,
        permissions=_permissions_from_str(permissions_str),
    )


@router.get(
    "/users/{domain}",
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
    },
)
async def all_users(
    domain: Domain,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> list[LDAPUser]:
    """
    ## List all enabled users that have non empty specified domain

    * Only admins can do this action
    """
    permissions = await session.scalar(
        permissions_api_stmt, {"user_id": auth_user.id}
    )
    if permissions < PermissionsAPI.admin:
        raise not_authorized_exception

    domain_field = {
        "extra": all_users_extra_stmt,
        "storage": all_users_storage_stmt,
        "git": all_users_git_stmt,
    }[domain]

    return [
        LDAPUser(
            username=username,
            display_name=display_name,
            email=email,
            permissions=_permissions_from_str(permissions_str),
        )
        for username, display_name, email, permissions_str in await session.execute(
            domain_field
        )
    ]


# class LDAPProject(BaseModel, strict=True, frozen=True):
#     project: str  # project-role format
#     members: list[str]


@router.get(
    "/roles/{domain}",
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
        status.HTTP_404_NOT_FOUND: response_description("User not found"),
    },
)
async def user_roles(
    domain: Domain,
    auth_user: Annotated[User, Depends(get_current_user)],
    username: str | None = None,
    session: AsyncSession = Depends(get_async_session),
) -> list[str]:
    """
    ## This is exactly like `find_user`, but the output is just list of roles

    * View current user roles, acceptable for everyone
    * Only admins can view roles of specified `username`
    """
    if username is None:
        user_id = auth_user.id
    else:
        permissions = await session.scalar(
            permissions_api_stmt, {"user_id": auth_user.id}
        )
        if permissions < PermissionsAPI.admin:
            raise not_authorized_exception

        user_id = await session.scalar(
            select_userid_by_username_stmt, {"username": username}
        )
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
    permissions_stmt = {
        "extra": permissions_extra_stmt,
        "git": permissions_git_stmt,
        "storage": permissions_storage_stmt,
    }[domain]
    permissions_str = await session.scalar(
        permissions_stmt, {"user_id": user_id}
    )
    return _permissions_from_str(permissions_str)
