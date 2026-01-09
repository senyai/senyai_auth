from __future__ import annotations
from typing import Annotated
from fastapi import APIRouter, Depends, status
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pydantic import (
    AfterValidator,
    constr,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from .blocklist import not_in_blocklist
from ..db import Project, User
from .. import get_async_session
from ..auth import get_current_user


router = APIRouter()

type ProjectId = Annotated[
    str,
    constr(min_length=2, max_length=32, to_lower=True, strip_whitespace=True),
    AfterValidator(not_in_blocklist),
]

type ProjectName = Annotated[
    str,
    constr(min_length=3, max_length=79, strip_whitespace=True),
    AfterValidator(not_in_blocklist),
]

type ProjectDescription = Annotated[str, constr(min_length=0, max_length=1024)]


class ProjectCreate(BaseModel):
    project_id: ProjectId
    name: ProjectName
    description: ProjectDescription

    def make_project(self):
        return Project(
            project_id=self.project_id,
            name=self.name,
            description=self.description,
        )


class ProjectUpdate(BaseModel):
    project_id: ProjectId | None = None
    name: ProjectName | None = None
    description: ProjectDescription | None = None

    def update(self, project: Project):
        for key, value in self.model_dump(
            exclude_unset=True, exclude_none=True
        ).items():
            setattr(project, key, value)


@router.post("/project", tags=["project"])
async def project(
    project: ProjectCreate,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    # ToDo: ensure correct right
    project_db = project.make_project()
    session.add(project_db)
    try:
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="project already exists",
        )
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={"project_id": project_db.id},
        headers={"Location": f"/project/{project_db.id}"},
    )


@router.patch("/project/{project_id}", tags=["project"])
async def update_project(
    project_id: int,
    project: ProjectUpdate,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> None:
    # ToDo: ensure correct right
    project_db = await session.get(Project, project_id)
    if project_db is None:
        raise HTTPException(status_code=404, detail="Project not found")
    project.update(project_db)
    session.add(project_db)
    await session.commit()


@router.get("/project/{project_id}", tags=["project"])
async def get_project(
    project_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    # ToDo: ensure correct right
    project_db = await session.get(Project, project_id)
    if project_db is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return {
        "project_id": project_db.project_id,
        "name": project_db.name,
        "description": project_db.description,
    }
