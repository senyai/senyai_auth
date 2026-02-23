from __future__ import annotations
from typing import Annotated
from fastapi import APIRouter, Depends, status
from fastapi.exceptions import HTTPException
from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    StringConstraints,
)
from sqlalchemy import delete, select, insert, literal
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from .blocklist import not_in_blocklist
from ..db import (
    auth_for_project_stmt,
    Member,
    MemberRole,
    permissions_api_stmt,
    PermissionsAPI,
    Project,
    Role,
    User,
)
from .. import get_async_session
from .auth import get_current_user
from .exceptions import (
    not_authorized_exception,
    response_description,
    response_with_perm_check,
)

router = APIRouter(tags=["project"])

type Name = Annotated[
    str,
    Field(description="Name as it will be used in url string"),
    StringConstraints(
        min_length=2, max_length=32, to_lower=True, strip_whitespace=True
    ),
    AfterValidator(not_in_blocklist),
]

type DisplayName = Annotated[
    str,
    Field(description="Name as it will be displayed in the title"),
    StringConstraints(min_length=3, max_length=79, strip_whitespace=True),
    AfterValidator(not_in_blocklist),
]

type Description = Annotated[str, StringConstraints(max_length=1024)]


class ProjectCreate(BaseModel, strict=True):
    name: Name
    display_name: DisplayName
    description: Description
    parent_id: Annotated[int, Field(strict=False)]

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
    parent: Annotated[
        int | str | None,
        Field(
            description="Only superadmin can reparent a project. Parent can "
            "be Project.id or Project.name. Changing parent can cause project "
            "to be missing in project list"
        ),
    ] = None

    def update(self, project: Project):
        for key, value in self.model_dump(
            exclude_unset=True, exclude_none=True, exclude={"parent"}
        ).items():
            setattr(project, key, value)


class NewProjectInfo(BaseModel, strict=True):
    project_id: int


@router.post(
    "/project",
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
    if "parent" in project.model_fields_set:
        user_permissions = await session.scalar(
            permissions_api_stmt, {"user_id": user.id}
        )
        if not user_permissions & PermissionsAPI.superadmin:
            raise not_authorized_exception
        parent = project.parent
        if isinstance(parent, str):
            parent_by_name = await session.scalar(
                select(Project.id).where(Project.name == parent)
            )
            if parent_by_name is None:
                raise HTTPException(
                    status_code=404, detail="Parent project not found"
                )
            parent = parent_by_name
        project_db.parent_id = parent

    project.update(project_db)
    session.add(project_db)
    await session.commit()


class ProjectModel(BaseModel, strict=True):
    name: str
    display_name: str
    description: str


@router.get(
    "/project/{project_id}",
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


class AddUserInfo(BaseModel, strict=True, frozen=True):
    id: int
    username: str
    email: str
    display_name: str

    @classmethod
    def from_user(cls, user: User):
        return cls(
            id=user.id,
            username=user.username,
            email=user.email,
            display_name=user.display_name,
        )


@router.get(
    "/project/{project_id}/add_users",
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
    },
)
async def project_list_possible_users(
    project_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> list[AddUserInfo]:
    """
    ## List all users that current user can add to the project

    * Only managers and above can do this
    """
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": user.id, "project_id": project_id},
    )
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception
    id_parent = select(Project.id)
    base = (
        id_parent.join(Role, Role.project_id == Project.id)
        .join(MemberRole, MemberRole.role_id == Role.id)
        .where(
            Role.permissions_api >= PermissionsAPI.manager,
            MemberRole.user_id == user.id,
        )
        .cte(name="base", recursive=True)
    )
    stmt_projects = select(
        base.union_all(
            id_parent.join(base, Project.parent_id == base.c.id),
        )
    )
    stmt = (
        select(User)
        .join(Member)
        .where(
            Member.project_id.in_(stmt_projects),
            Member.project_id != project_id,
        )
        .distinct()
    )
    return [
        AddUserInfo.from_user(user) for user in await session.scalars(stmt)
    ]


@router.post(
    "/project/{project_id}/users",
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
    },
)
async def project_add_users(
    project_id: int,
    user_ids: list[int],
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    """
    ## Add users to a project

    * Only managers and above can do this
    """
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": user.id, "project_id": project_id},
    )
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception
    await session.execute(
        insert(Member).from_select(
            ("project_id", "user_id"),
            select(literal(project_id).label("project_id"), User.id).where(
                User.id.in_(user_ids)
            ),
        )
    )
    await session.commit()


@router.delete(
    "/project/{project_id}/users",
    responses={
        status.HTTP_401_UNAUTHORIZED: response_with_perm_check,
        status.HTTP_404_NOT_FOUND: response_description("Project not found"),
    },
)
async def project_remove_users(
    project_id: int,
    user_ids: list[int],
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    """
    ## Remove users from a project

    * Only managers and above can do this
    * Also removes users from Project's Roles
    """
    permission = await session.scalar(
        auth_for_project_stmt,
        {"user_id": user.id, "project_id": project_id},
    )
    if permission < PermissionsAPI.manager:
        raise not_authorized_exception
    # remove project members
    await session.execute(
        delete(Member).where(
            Member.project_id == project_id, Member.user_id.in_(user_ids)
        )
    )
    # remove these members from roles too
    await session.execute(
        select(MemberRole)
        .join(Role)
        .where(Role.project_id == project_id, MemberRole.user_id.in_(user_ids))
    )
    await session.commit()
