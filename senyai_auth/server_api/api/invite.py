from __future__ import annotations
from typing import Annotated
import os
import base64
from pydantic import (
    AfterValidator,
    BaseModel,
    StringConstraints,
    Field,
)
from .blocklist import not_in_blocklist
from fastapi import APIRouter, status, Depends, Response, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete, select

from ..db import User, Invitation
from .auth import get_current_user
from .exceptions import (
    not_authorized_exception,
    response_description,
    response_with_perm_check,
)
from .. import get_async_session
from ..db import auth_for_project_stmt, PermissionsAPI

router = APIRouter(tags=["invite"])


def _get_key_32() -> str:
    """
    Random url friendly string
    """
    return base64.urlsafe_b64encode(os.urandom(24)).decode()


class InviteUserModel(BaseModel, strict=True, frozen=True):
    project_id: Annotated[
        int,
        Field(
            description="After user accepts invitation,"
            "it will be added to the project. No roles will be assigned"
        ),
    ]
    prompt: Annotated[
        str,
        StringConstraints(max_length=1024, strip_whitespace=True),
        Field(description="Show invitation above user registration form."),
    ]
    default_username: Annotated[
        str,
        StringConstraints(
            min_length=0,
            max_length=32,
            to_lower=True,
            strip_whitespace=True,
            pattern=r"^[a-z_-]*$",
        ),
        AfterValidator(not_in_blocklist),
        Field(
            description="User will have username field filled for convenience."
        ),
    ]
    default_email: Annotated[
        str,
        StringConstraints(
            min_length=0,
            max_length=500,
            strip_whitespace=True,
            pattern=r"^\S*$",
        ),
        Field(description="For convenience. Should be left empty."),
    ]

    default_display_name: Annotated[
        str,
        StringConstraints(
            min_length=0,
            max_length=79,
            strip_whitespace=True,
            pattern=r"^[\w ]*$",
        ),
        Field(
            description="User will have display_name field filled "
            "for convenience and to allow to see the name of the person "
            "who awaits/got invitation"
        ),
    ]

    roles: Annotated[
        list[str],  # list of `Role.name`` for current `project_id`
        Field(
            description="Assign these roles after user accepts invitation. "
            "If anything has happened  with roles before invitation is "
            "accepted, roles will not be applied."
        ),
    ]

    def make_invitation_by(self, inviter: User) -> Invitation:
        url_key = _get_key_32()
        return Invitation(
            url_key=url_key,
            project_id=self.project_id,
            roles=self.roles,
            inviter=inviter,
            prompt=self.prompt,
            default_username=self.default_username,
            default_display_name=self.default_display_name,
            default_email=self.default_email,
        )


class InviteResult(BaseModel, strict=True):
    url_key: str


@router.post(
    "/invite",
    status_code=status.HTTP_201_CREATED,
    responses={status.HTTP_401_UNAUTHORIZED: response_with_perm_check},
)
async def invite_user(
    user: InviteUserModel,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> InviteResult:
    """
    ## Create new invite

    Only managers can do it
    """
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": auth_user.id, "project_id": user.project_id},
    )
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception

    invitation_db = user.make_invitation_by(auth_user)
    session.add(invitation_db)
    await session.commit()
    return InviteResult(url_key=invitation_db.url_key)


class InvitationForm(BaseModel, strict=True):
    """
    What to show when user opens invitation
    """

    prompt: str
    username: str
    display_name: str
    email: str


@router.get(
    "/invite/{key}",
    responses={
        status.HTTP_404_NOT_FOUND: response_description(
            "Invitation not found or already accepted"
        ),
    },
)
async def get_invitation(
    key: str,
    session: AsyncSession = Depends(get_async_session),
) -> InvitationForm:
    """
    ## For "Create New User" page
    """
    invitation = await session.scalar(
        select(Invitation).where(
            Invitation.url_key == key,
        )
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
    return InvitationForm(
        prompt=invitation.prompt,
        username=invitation.default_username,
        display_name=invitation.default_display_name,
        email=invitation.default_email,
    )


@router.delete(
    "/invite/{key}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
        status.HTTP_404_NOT_FOUND: response_description(
            "Invitation not found"
        ),
    },
)
async def delete_invitation(
    key: str,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> Response:
    """
    ## Delete a single invite

    Only superadmins can do it
    """
    invitation = await session.scalar(
        select(Invitation).where(
            Invitation.url_key == key,
        )
    )
    if invitation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": auth_user.id, "project_id": invitation.project_id},
    )
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception

    await session.delete(invitation)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


class InviteEntry(BaseModel, strict=True):
    url_key: str
    display_name: str
    accepted_id: int | None


@router.get(
    "/invites/{project_id}",
    responses={status.HTTP_401_UNAUTHORIZED: response_with_perm_check},
)
async def list_invites(
    project_id: int,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> list[InviteEntry]:
    """
    ## List invites for a project.

    Only managers have access to this list.
    """
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": auth_user.id, "project_id": project_id},
    )
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception

    invitations = await session.execute(
        select(
            Invitation.url_key,
            Invitation.default_display_name,
            Invitation.who_accepted_id,
        ).where(Invitation.project_id == project_id)
    )
    ret: list[InviteEntry] = []
    for url_key, display_name, accepted_id in invitations:
        ret.append(
            InviteEntry(
                url_key=url_key,
                display_name=display_name,
                accepted_id=accepted_id,
            )
        )
    return ret
