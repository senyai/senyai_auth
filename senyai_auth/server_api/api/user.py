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

from ..db import (
    all_permissions_stmt,
    Invitation,
    Member,
    PermissionsAPI,
    Project,
    Role,
    User,
)
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


class CreateUserModel(BaseModel, strict=True, frozen=True):
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
    contacts: Annotated[
        str,
        constr(
            min_length=0,
            max_length=1500,
        ),
        Field(description="User telephone and address. Can be empty."),
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

    @staticmethod
    def make_salt() -> str:
        return base64.b85encode(os.urandom(16)).decode()

    def make_user(self) -> User:
        salt = self.make_salt()
        password_hash = User.create_password_hash(
            password=self.password.get_secret_value(), salt=salt
        )
        return User(
            username=self.username,
            password_hash=password_hash,
            salt=salt,
            email=self.email,
            contacts=self.contacts,
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


class PasswordModel(BaseModel, strict=True, frozen=True):
    old: Annotated[
        SecretStr, constr(min_length=8, max_length=64, strip_whitespace=True)
    ] = Field(exclude=True)
    new: Annotated[
        SecretStr, constr(min_length=8, max_length=64, strip_whitespace=True)
    ] = Field(exclude=True)


class UpdateUserModel(BaseModel, strict=True, frozen=True):
    username: Annotated[
        str | None,
        constr(
            min_length=2,
            max_length=32,
            to_lower=True,
            strip_whitespace=True,
            pattern=r"^[a-z_-]+$",
        ),
        AfterValidator(not_in_blocklist),
    ] = None
    password: PasswordModel | None = None
    email: Annotated[
        str | None,
        constr(
            min_length=3,
            max_length=500,
            strip_whitespace=True,
            pattern=r"^\W*$",
        ),
    ] = None
    contacts: Annotated[
        str | None,
        constr(
            min_length=0,
            max_length=1500,
        ),
        Field(description="User telephone and address. Can be empty."),
    ] = None
    display_name: Annotated[
        str | None,
        constr(
            min_length=3,
            max_length=79,
            strip_whitespace=True,
            pattern=r"^[\W ]*$",
        ),
    ] = None
    disabled: Annotated[
        bool | None,
        Field(description="User won't be able to login when disabled"),
    ] = None

    def update(self, user: User, is_superadmin: bool) -> None:
        if self.password is not None:
            current_password_hash = user.create_password_hash(
                self.password.old.get_secret_value(), user.salt
            )
            if current_password_hash != user.password_hash:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Current password does not match",
                )
            new_salt = CreateUserModel.make_salt()
            new_password_hash = user.create_password_hash(
                self.password.new.get_secret_value(), new_salt
            )
            user.salt = new_salt
            user.password_hash = new_password_hash
        if self.username is not None and not is_superadmin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only Administrator can change user's username",
            )
        for key, value in self.model_dump(
            exclude_unset=True, exclude_none=True, exclude={"password"}
        ).items():
            setattr(user, key, value)


class UserInfo(BaseModel, strict=True, frozen=True):
    id: int
    username: str
    email: str
    contacts: str
    display_name: str
    permissions_api: list[tuple[str, str]]

    @classmethod
    def from_user(cls, user: User, permissions_api: list[tuple[str, str]]):
        return cls(
            id=user.id,
            username=user.username,
            email=user.email,
            contacts=user.contacts,
            display_name=user.display_name,
            permissions_api=permissions_api,
        )


@router.get("/user", tags=["user"])
async def get_user(
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    """
    ## Information for "Update User" form
    """
    stmt = (
        select(Project.name, Role.permissions_api)
        .join(Member)
        .join(Role)
        .where(Member.user == auth_user)
    )
    auth_user = await session.merge(auth_user)
    await session.refresh(auth_user, attribute_names=("contacts",))
    permissions_api = await session.execute(stmt)
    return UserInfo.from_user(
        auth_user, [(name, perm.name) for name, perm in permissions_api]
    )


@router.patch(
    "/user/{user_id}", tags=["user"], status_code=status.HTTP_204_NO_CONTENT
)
async def update_user(
    user_id: int,
    user: UpdateUserModel,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    """
    ## Update user attributes

    *username* can only be changed by superadmin
    """
    permissions = await session.scalar(
        all_permissions_stmt, {"user_id": auth_user.id}
    )
    is_superadmin: bool = permissions & PermissionsAPI.superadmin
    if not is_superadmin and auth_user.id != user_id:
        raise not_authorized_exception
    user.update(auth_user, is_superadmin)
    session.add(auth_user)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete(
    "/user/{user_id}", tags=["user"], status_code=status.HTTP_204_NO_CONTENT
)
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/register/{key}",
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )
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
