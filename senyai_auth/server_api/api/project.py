from __future__ import annotations
from typing import Annotated
from fastapi import APIRouter, Depends, status, Response
from fastapi.exceptions import HTTPException
from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    constr,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from .blocklist import not_in_blocklist
from ..db import Project, User, auth_for_project_stmt, PermissionsAPI
from .. import get_async_session
from .auth import get_current_user
from .exceptions import (
    not_authorized_exception,
    response_description,
    response_with_perm_check,
)


router = APIRouter()

type Name = Annotated[
    str,
    Field(description="Name as it will be used in url string"),
    constr(min_length=2, max_length=32, to_lower=True, strip_whitespace=True),
    AfterValidator(not_in_blocklist),
]

type DisplayName = Annotated[
    str,
    Field(description="Name as it will be displayed in the title"),
    constr(min_length=3, max_length=79, strip_whitespace=True),
    AfterValidator(not_in_blocklist),
]

type Description = Annotated[str, constr(max_length=1024)]


class ProjectCreate(BaseModel, strict=True):
    name: Name
    display_name: DisplayName
    description: Description
    parent_id: int

    def make_project(self):
        return Project(
            name=self.name,
            display_name=self.display_name,
            description=self.description,
            parent_id=self.parent_id,
        )


class ProjectUpdate(BaseModel, strict=True):
    name: Name | None = None
    display_name: DisplayName | None = None
    description: Description | None = None

    def update(self, project: Project):
        for key, value in self.model_dump(
            exclude_unset=True, exclude_none=True
        ).items():
            setattr(project, key, value)


class NewProjectInfo(BaseModel, strict=True):
    project_id: int


@router.post(
    "/project",
    tags=["project"],
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
        status.HTTP_409_CONFLICT: response_description(
            "Project already exists"
        ),
    },
)
async def new_project(
    project: ProjectCreate,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> NewProjectInfo:
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": user.id, "project_id": project.parent_id},
    )
    if permission < PermissionsAPI.user:
        raise not_authorized_exception
    project_db = project.make_project()
    session.add(project_db)
    try:
        await session.commit()
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Project '{project.name}' already exists",
        )
    return NewProjectInfo(project_id=project_db.id)


@router.patch(
    "/project/{project_id}",
    tags=["project"],
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
        status.HTTP_404_NOT_FOUND: response_description("Project not found"),
    },
)
async def update_project(
    project_id: int,
    project: ProjectUpdate,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> None:
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": user.id, "project_id": project_id},
    )
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception
    # Don't allow manager to change project name
    if project.name is not None and permission < PermissionsAPI.admin:
        raise not_authorized_exception
    project_db = await session.get(Project, project_id)
    if project_db is None:
        raise HTTPException(status_code=404, detail="Project not found")
    project.update(project_db)
    session.add(project_db)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


class ProjectModel(BaseModel, strict=True):
    name: str
    display_name: str
    description: str


@router.get(
    "/project/{project_id}",
    tags=["project"],
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
        status.HTTP_404_NOT_FOUND: response_description("Project not found"),
    },
)
async def get_project(
    project_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> ProjectModel:
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": user.id, "project_id": project_id},
    )
    if permission < PermissionsAPI.user:
        raise not_authorized_exception
    project_db = await session.get(Project, project_id)
    if project_db is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return ProjectModel(
        name=project_db.name,
        display_name=project_db.display_name,
        description=project_db.description,
    )
