from __future__ import annotations
from typing import Annotated
import os
import base64
from pydantic import (
    AfterValidator,
    BaseModel,
    constr,
    Field,
    model_validator,
    SecretStr,
)
from .blocklist import not_in_blocklist
from fastapi import APIRouter, status, Depends, Response, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from zxcvbn import zxcvbn

from ..db import User, Invitation, all_permissions_stmt, PermissionsAPI, Member
from ..auth import get_current_user, not_authorized_exception
from .. import get_async_session


router = APIRouter()


def check_password(
    password: str, username: str, email: str, display_name: str
) -> None:
    validation = zxcvbn(
        password=password,
        user_inputs=[username, email, display_name],
    )
    feedback = validation["feedback"]
    if validation["score"] <= 2 or validation["guesses_log10"] < 8:
        raise ValueError(
            f"Password is too weak {feedback['warning']}, "
            f"{''.join(feedback['suggestions'])}"
        )


class CreateUserModel(BaseModel):
    username: Annotated[
        str,
        constr(
            min_length=2,
            max_length=32,
            to_lower=True,
            strip_whitespace=True,
            pattern=r"^[a-z_-]+$",
        ),
        AfterValidator(not_in_blocklist),
    ]
    password: Annotated[
        SecretStr, constr(min_length=8, max_length=64, strip_whitespace=True)
    ] = Field(exclude=True)
    email: Annotated[
        str,
        constr(
            min_length=3,
            max_length=500,
            strip_whitespace=True,
            pattern=r"^\W*$",
        ),
    ]
    display_name: Annotated[
        str,
        constr(
            min_length=3,
            max_length=79,
            strip_whitespace=True,
            pattern=r"^[\W ]*$",
        ),
    ]

    @model_validator(mode="after")
    def check_strong_password(self):
        check_password(
            self.password.get_secret_value(),
            self.username,
            self.email,
            self.display_name,
        )
        return self

    def make_user(self) -> User:
        salt = base64.b85encode(os.urandom(16)).decode()
        password_hash = User.create_password_hash(
            password=self.password.get_secret_value(), salt=salt
        )
        return User(
            username=self.username,
            password_hash=password_hash,
            salt=salt,
            email=self.email,
            display_name=self.display_name,
        )


class NewUserResponse(BaseModel, strict=True):
    user_id: int


@router.post(
    "/user",
    tags=["user"],
    status_code=status.HTTP_201_CREATED,
    response_model=NewUserResponse,
)
async def create_user(
    user: CreateUserModel,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    """
    ## Create a new user.

    Who can do it:

    * Superadmin
    """
    permissions = await session.scalar(
        all_permissions_stmt, {"user_id": auth_user.id}
    )
    if not permissions & PermissionsAPI.superadmin:
        raise not_authorized_exception
    user_db = user.make_user()
    session.add(user_db)
    try:
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"user {user.username} already exists",
        )
    return NewUserResponse(user_id=user_db.id)


@router.post(
    "/user/{key}",
    tags=["user"],
    status_code=status.HTTP_201_CREATED,
    response_model=NewUserResponse,
)
async def create_user_by_invitation(
    key: str,
    user: CreateUserModel,
    session: AsyncSession = Depends(get_async_session),
):
    """
    ## Create a new user.

    Using invitation key
    """
    invitation = await session.scalar(
        select(Invitation).where(
            Invitation.url_key == key, Invitation.who_accepted_id == None
        )
    )
    if invitation is None:
        raise HTTPException(status_code=404, detail="Invitation not found")
    user_db = user.make_user()
    invitation.who_accepted = user_db
    session.add(Member(project_id=invitation.project_id, user=user_db))
    session.add(invitation)
    session.add(user_db)
    try:
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"user {user.username} already exists",
        )
    return NewUserResponse(user_id=user_db.id)


@router.delete("/user", tags=["user"], status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    """
    ## Delete user

    Should only be possible by superadmin
    """
    permissions = await session.scalar(
        all_permissions_stmt, {"user_id": auth_user.id}
    )
    if not permissions & PermissionsAPI.superadmin:
        raise not_authorized_exception
    affected = await session.execute(delete(User).where(User.id == user_id))
    if affected.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
