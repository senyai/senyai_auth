from __future__ import annotations
from typing import Annotated
from pydantic import BaseModel, BeforeValidator
from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import Role, User, auth_for_project_stmt, PermissionsAPI
from ..auth import get_current_user, not_authorized_exception
from .. import get_async_session
from .project import Name, Description

router = APIRouter()


def validate_api(value: str) -> PermissionsAPI:
    try:
        return PermissionsAPI[value]
    except KeyError:
        raise ValueError(
            f"Invalid permission: {value}. "
            f"Must be one of: {', '.join(p.name for p in PermissionsAPI)}"
        )


class RoleCreate(BaseModel):
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


@router.post("/role", tags=["role"])
async def new_role(
    role: RoleCreate,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    """
    ## Create Role for a project
    """
    permission = (
        await session.execute(
            auth_for_project_stmt,
            {"user_id": user.id, "project_id": role.project_id},
        )
    ).scalar()
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception
    role_db = role.make_role()
    session.add(role_db)
    try:
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="project already exists",
        )
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={"role_id": role_db.id},
        headers={"Location": f"/project/{role_db.id}"},
    )


class RoleUpdate(BaseModel):
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


@router.patch("/role/{role_id}", tags=["role"])
async def update_role(
    role_id: int,
    role: RoleUpdate,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    role_db = await session.get(Role, role_id)
    if role_db is None:
        raise HTTPException(status_code=404, detail="Role not found")
    permission = (
        await session.execute(
            auth_for_project_stmt,
            {"user_id": user.id, "project_id": role_db.project_id},
        )
    ).scalar()
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception
    role.update(role_db)
    session.add(role_db)
    await session.commit()


@router.delete("/role/{role_id}", tags=["role"])
async def delete_role(
    role_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    role_db = await session.get(Role, role_id)
    if role_db is None:
        raise HTTPException(status_code=404, detail="Role not found")
    permission = (
        await session.execute(
            auth_for_project_stmt,
            {"user_id": user.id, "project_id": role_db.project_id},
        )
    ).scalar()
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception
    await session.delete(role_db)
    await session.flush()


@router.post("/role/{role}/user/{user}", tags=["role"])
async def add_user_to_a_role(
    role: int | str,
    user: int | str,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    breakpoint()
    if isinstance(role, int):
        role_db = await session.get(Role, role)
    else:
        role_db = (
            await session.execute(select(Role).where(Role.name == role))
        ).scalar()
