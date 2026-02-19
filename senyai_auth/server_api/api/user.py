from __future__ import annotations
from typing import Annotated, Literal
from pydantic import (
    AfterValidator,
    BaseModel,
    StringConstraints,
    Field,
    model_validator,
    SecretStr,
    EmailStr,
)
from .blocklist import not_in_blocklist
from fastapi import APIRouter, status, Depends, Response, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert, delete, literal
from zxcvbn import zxcvbn

from ..db import (
    Invitation,
    Member,
    permissions_api_stmt,
    permissions_extra_stmt,
    permissions_git_stmt,
    permissions_storage_stmt,
    PermissionsAPI,
    MemberRole,
    Role,
    User,
)
from .auth import get_current_user
from .. import get_async_session
from .exceptions import (
    not_authorized_exception,
    response_with_perm_check,
    response_description,
)

router = APIRouter(tags=["user"])


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
        StringConstraints(
            min_length=2,
            max_length=32,
            to_lower=True,
            strip_whitespace=True,
            pattern=r"^[a-z0-9_-]+$",
        ),
        AfterValidator(not_in_blocklist),
    ]
    password: SecretStr = Field(exclude=True, min_length=8, max_length=64)
    email: EmailStr
    contacts: Annotated[
        str,
        StringConstraints(
            min_length=0,
            max_length=1500,
        ),
        Field(description="User telephone and address. Can be empty."),
    ]
    display_name: Annotated[
        str,
        StringConstraints(
            min_length=3,
            max_length=79,
            strip_whitespace=True,
            pattern=r"^[\w ]*$",
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
        salt = User.make_salt()
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
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
        status.HTTP_409_CONFLICT: response_description("User already exists"),
    },
)
async def create_user(
    user: CreateUserModel,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> NewUserResponse:
    """
    ## Create a new user.

    Who can do it:

    * Superadmin
    """
    permissions = await session.scalar(
        permissions_api_stmt, {"user_id": auth_user.id}
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
            detail=f"User {user.username} already exists",
        )
    return NewUserResponse(user_id=user_db.id)


class PasswordModel(BaseModel, strict=True, frozen=True):
    old: SecretStr = Field(min_length=8, max_length=64, exclude=True)
    new: SecretStr = Field(min_length=8, max_length=64, exclude=True)


class UpdateUserModel(BaseModel, strict=True, frozen=True):
    username: Annotated[
        str | None,
        StringConstraints(
            min_length=2,
            max_length=32,
            to_lower=True,
            strip_whitespace=True,
            pattern=r"^[a-z_-]+$",
        ),
        AfterValidator(not_in_blocklist),
    ] = None
    password: PasswordModel | None = None
    email: EmailStr | None = None
    contacts: Annotated[
        str | None,
        StringConstraints(
            min_length=0,
            max_length=1500,
        ),
        Field(description="User telephone and address. Can be empty."),
    ] = None
    display_name: Annotated[
        str | None,
        StringConstraints(
            min_length=3,
            max_length=79,
            strip_whitespace=True,
            pattern=r"^[\w ]*$",
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
            user.update_password(self.password.new.get_secret_value())
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

    @classmethod
    def from_user(cls, user: User):
        return cls(
            id=user.id,
            username=user.username,
            email=user.email,
            contacts=user.contacts,
            display_name=user.display_name,
        )


@router.get(
    "/user",
    responses={status.HTTP_401_UNAUTHORIZED: response_with_perm_check},
)
async def get_user(
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> UserInfo:
    """
    ## Information for "Update User" form
    """
    auth_user = await session.merge(auth_user)
    await session.refresh(
        auth_user, attribute_names=("contacts", "email", "display_name")
    )
    return UserInfo.from_user(auth_user)


@router.patch(
    "/user/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        status.HTTP_400_BAD_REQUEST: response_description(
            "Current password does not match"
        ),
        status.HTTP_403_FORBIDDEN: response_description(
            "Only Administrator can change user's username"
        ),
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
    },
)
async def update_user(
    user_id: int,
    user: UpdateUserModel,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> None:
    """
    ## Update user attributes

    *username* can only be changed by superadmin
    """
    permissions = await session.scalar(
        permissions_api_stmt, {"user_id": auth_user.id}
    )
    is_superadmin: bool = permissions & PermissionsAPI.superadmin
    if not is_superadmin and auth_user.id != user_id:
        raise not_authorized_exception
    user.update(auth_user, is_superadmin)
    session.add(auth_user)
    await session.commit()


@router.delete(
    "/user/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={status.HTTP_401_UNAUTHORIZED: response_with_perm_check},
)
async def delete_user(
    user_id: int,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> Response:
    """
    ## Delete user

    Should only be possible by superadmin
    """
    permissions = await session.scalar(
        permissions_api_stmt, {"user_id": auth_user.id}
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
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
        status.HTTP_404_NOT_FOUND: response_description(
            "Invitation not found or already accepted"
        ),
        status.HTTP_409_CONFLICT: response_description("User already exists"),
    },
)
async def create_user_by_invitation(
    key: str,
    user: CreateUserModel,
    session: AsyncSession = Depends(get_async_session),
) -> NewUserResponse:
    """
    ## Create a new user.

    Using invitation key
    """
    invitation = await session.scalar(
        select(Invitation).where(Invitation.url_key == key)
    )
    if invitation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )
    if invitation.who_accepted_id is not None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation already accepted",
        )
    user_db = user.make_user()
    invitation.who_accepted = user_db
    session.add(Member(project_id=invitation.project_id, user=user_db))
    session.add(invitation)
    session.add(user_db)
    await session.flush((user_db,))
    await session.execute(
        insert(MemberRole).from_select(
            ("user_id", "role_id"),
            select(
                literal(user_db.id).label("user_id"), Role.id.label("role_id")
            ).where(
                Role.project_id == invitation.project_id,
                Role.name.in_(invitation.roles),
            ),
        )
    )

    try:
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User {user.username} already exists",
        )
    return NewUserResponse(user_id=user_db.id)


permissions_stmt = {
    "extra": permissions_extra_stmt,
    "git": permissions_git_stmt,
    "storage": permissions_storage_stmt,
}


@router.get(
    "/permissions/{service}",
    tags=["auth"],
    responses={
        status.HTTP_401_UNAUTHORIZED: response_description(
            "Incorrect username or password"
        )
    },
)
async def permissions_storage(
    service: Literal["storage", "git", "extra"],
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> list[str]:
    res = await session.scalar(
        permissions_stmt[service], {"user_id": auth_user.id}
    )
    if res is None:
        return []
    return sorted(set(res.split(" ")))
