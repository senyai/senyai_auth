from __future__ import annotations
from typing import Annotated
from pydantic import BaseModel
from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import Role, User
from ..auth import get_current_user
from .. import get_async_session
from .project import ProjectName, ProjectDescription

router = APIRouter()


class RoleCreate(BaseModel):
    project_id: int
    name: ProjectName
    description: ProjectDescription = ""
    permissions_api: str = ""
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
    name: ProjectName | None = None
    description: ProjectDescription | None = None
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
    # ToDo: ensure permissions
    role.update(role_db)
    session.add(role_db)
    await session.commit()
