"""
Tried https://github.com/fief-dev/fief, but the vibe is off
"""

from __future__ import annotations

from typing import Annotated
import os
import base64
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from pydantic import (
    AfterValidator,
    BaseModel,
    constr,
    Field,
    model_validator,
    SecretStr,
)
from fastapi import status
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from zxcvbn import zxcvbn
from . import app
from .db import User, Project, Member, Role, MemberRole
from .auth import get_current_user, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from typing import AsyncGenerator


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with app.state.async_session() as session:
        yield session


@app.get("/")
async def root(
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    """
    A way for a user to get brief information about auth status
    """
    stmt = (
        select(Project.id, Project.name)
        .join(Member)
        .where(Member.user_id == user.id)
    )
    # user2 = await session.merge(user, load=False)
    projects = (await session.execute(stmt)).scalars()
    return {"projects": projects}


def not_in_blocklist(name: str) -> str:
    bad_names = (
        "admin",
        "administrator",
        "root",
        "sysadmin",
        "administrator1",
        "admin1",
        "adminroot",
        "superadmin",
        "supervisor",
        "manager",
        "owner",
        "webadmin",
        "webmaster",
        "support",
        "postmaster",
        "hostmaster",
        "ftp",
        "ftpadmin",
        "dbadmin",
        "oracle",
        "postgres",
        "sqladmin",
        "ubuntu",
        "adminuser",
    )

    if name in bad_names or name.startswith("admin") or name.endswith("admin"):
        raise ValueError("is blocked because it is suspicious")
    return name


class CreateUserModel(BaseModel):
    username: Annotated[
        str,
        constr(
            min_length=2,
            max_length=32,
            to_lower=True,
            strip_whitespace=True,
            pattern=r"^[a-z_]+$",
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
        validation = zxcvbn(
            password=self.password.get_secret_value(),
            user_inputs=[self.username, self.email, self.display_name],
        )
        feedback = validation["feedback"]
        if validation["score"] <= 2 or validation["guesses_log10"] < 8:
            raise ValueError(
                f"Password is too weak {feedback['warning']}, "
                f"{''.join(feedback['suggestions'])}"
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


@app.post("/user")
async def user(
    user: CreateUserModel,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    """
    ## Create a new user.

    Who can do it:

    * Superadmin
    * User, using special one time auth link. will be implemented later
    """
    # ToDo: ensure correct right
    auth_stmt = select(Role.name).where(
        Role.permissions_api == "superadmin", MemberRole.user == auth_user
    )
    user_db = user.make_user()
    dbg = await session.execute(auth_stmt)
    breakpoint()
    session.add(user_db)
    try:
        await session.commit()
    except IntegrityError:
        raise ValueError("user already exists")
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={"user_id": user_db.id},
        headers={"Location": f"/user/{user_db.id}"},
    )


@app.delete("/user")
async def delete_user(
    user: CreateUserModel,
    auth_user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    """
    ## Delete user

    Right now should only be possible by superadmin
    """


@app.get("/users")
async def users(
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    users = await session.execute(select(User))
    ret = list(users.scalars())
    return ret


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
    project_id: ProjectId | None
    name: ProjectName | None
    description: ProjectDescription | None

    def update_project(self, project: Project):
        for key, value in self.model_dump(
            exclude_unset=True, exclude_none=True
        ):
            setattr(project, key, value)


@app.post("/project")
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


@app.patch("/project/{project_id}")
async def update_project(
    project: ProjectUpdate,
    project_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> None:
    # ToDo: ensure correct right
    project_db = await session.get(Project, project_id)
    if project_db is None:
        raise HTTPException(status_code=404, detail="Project not found")
    project.update_project(project_db)
    session.add(project_db)
    await session.commit()


@app.get("/project/{project_id}")
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


@app.get("/projects")
async def projects(
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
):
    session.add(project_db)
    try:
        await session.commit()
    except IntegrityError:
        raise ValueError("project already exists")
    return project_db.id


class UserInfo(BaseModel):
    username: str
    email: str
    display_name: str
    permissions_api: list[tuple[str, str]]

    @classmethod
    def from_user(cls, user: User, permissions_api: list[tuple[str, str]]):
        return cls(
            username=user.username,
            email=user.email,
            display_name=user.display_name,
            permissions_api=permissions_api,
        )


@app.get("/whoami")
async def whoami(
    user: Annotated[User, Depends(get_current_user)],
    session: AsyncSession = Depends(get_async_session),
) -> UserInfo:
    stmt = (
        select(Project.name, Role.permissions_api)
        .join(Member)
        .join(Role)
        .where(Member.user == user)
    )
    permissions_api = await session.execute(stmt)
    return UserInfo.from_user(user, [tuple(row) for row in permissions_api])
