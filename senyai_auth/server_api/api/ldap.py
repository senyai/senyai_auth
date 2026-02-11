from __future__ import annotations
from typing import Annotated
from pydantic import BaseModel, StringConstraints
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import (
    PermissionsAPI,
    User,
    permissions_api_stmt,
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
    """
    permissions = await session.scalar(
        permissions_api_stmt, {"user_id": auth_user.id}
    )
    if not permissions & PermissionsAPI.superadmin:
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
