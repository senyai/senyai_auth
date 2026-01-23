from __future__ import annotations
from typing import Annotated
from pydantic import BaseModel, BeforeValidator
from fastapi import APIRouter, Depends, status, HTTPException, Response
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import Role, User, auth_for_project_stmt, PermissionsAPI, MemberRole
from .auth import get_current_user
from .. import get_async_session
from .project import Name, Description
from .exceptions import (
    not_authorized_exception,
    response_description,
    response_with_perm_check,
)

router = APIRouter(tags=["role"])


def validate_api(value: str) -> PermissionsAPI:
    try:
        return PermissionsAPI[value]
    except KeyError:
        raise ValueError(
            f"Invalid permission: {value}. "
            f"Must be one of: {', '.join(p.name for p in PermissionsAPI)}"
        )


class RoleCreate(BaseModel, strict=True, frozen=True):
    project_id: int
    name: Name
    description: Description = ""
    permissions_api: Annotated[
        PermissionsAPI, BeforeValidator(validate_api)
    ] = PermissionsAPI.none
    permissions_git: str = ""
    permissions_storage: str = ""
    permissions_extra: str = ""

    def make_role(self):
        return Role(
            project_id=self.project_id,
            name=self.name,
            description=self.description,
            permissions_api=self.permissions_api,
            permissions_git=self.permissions_git,
            permissions_storage=self.permissions_storage,
            permissions_extra=self.permissions_extra,
        )


class RoleModel(BaseModel, strict=True):
    role_id: int


@router.post(
    "/role",
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
        status.HTTP_409_CONFLICT: response_description(
            "Role with that name already exists"
        ),
    },
)
async def new_role(
    role: RoleCreate,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> RoleModel:
    """
    ## Create Role for a project
    """
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": user.id, "project_id": role.project_id},
    )
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception
    role_db = role.make_role()
    session.add(role_db)
    try:
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Role with that name already exists",
        )
    return RoleModel(role_id=role_db.id)


class RoleUpdate(BaseModel, strict=True, frozen=True):
    name: Name | None = None
    description: Description | None = None
    permissions_api: str | None = None
    permissions_git: str | None = None
    permissions_storage: str | None = None
    permissions_extra: str | None = None

    def update(self, role: Role) -> None:
        for key, value in self.model_dump(
            exclude_unset=True, exclude_none=True
        ).items():
            setattr(role, key, value)


@router.patch(
    "/role/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
        status.HTTP_404_NOT_FOUND: response_description("Role not found"),
    },
)
async def update_role(
    role_id: int,
    role: RoleUpdate,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> Response:
    role_db = await session.get(Role, role_id)
    if role_db is None:
        raise HTTPException(status_code=404, detail="Role not found")
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": user.id, "project_id": role_db.project_id},
    )
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception
    role.update(role_db)
    session.add(role_db)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete(
    "/role/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
        status.HTTP_404_NOT_FOUND: response_description("Role not found"),
    },
)
async def delete_role(
    role_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> Response:
    role_db = await session.get(Role, role_id)
    if role_db is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": user.id, "project_id": role_db.project_id},
    )
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception
    await session.delete(role_db)
    await session.flush()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/role/{role_id}/users",
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
        status.HTTP_404_NOT_FOUND: response_description("Role not found"),
    },
)
async def add_users_to_a_role(
    role_id: int,
    user_ids: list[int],
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> Response:
    role_db = await session.get(Role, role_id)
    if role_db is None:
        raise HTTPException(status_code=404, detail="Role not found")
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": auth_user.id, "project_id": role_db.project_id},
    )
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception

    # ToDo: uid are unchecked - fix that
    member_roles = [MemberRole(user_id=uid, role=role_db) for uid in user_ids]
    session.add_all(member_roles)
    await session.commit()
    return Response(status_code=status.HTTP_201_CREATED)


@router.delete(
    "/role/{role_id}/users",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
        status.HTTP_404_NOT_FOUND: response_description("Role not found"),
    },
)
async def remove_users_from_role(
    role_id: int,
    user_ids: list[int],
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> Response:
    role_db = await session.get(Role, role_id)
    if role_db is None:
        raise HTTPException(status_code=404, detail="Role not found")
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": auth_user.id, "project_id": role_db.project_id},
    )
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception

    affected = await session.execute(
        delete(MemberRole).where(
            MemberRole.role_id == role_id, MemberRole.role_id.in_(user_ids)
        )
    )
    if affected.rowcount == 0:
        raise HTTPException(status_code=404, detail="No users were removed")
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
