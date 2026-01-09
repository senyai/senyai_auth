from __future__ import annotations

from typing import Literal
from sqlalchemy import func, ForeignKey, UniqueConstraint
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)
from datetime import datetime
from pyargon2 import hash as pyargon2_hash
from sqlalchemy import select


class Base(DeclarativeBase):
    pass


#
# What to read to understand how to write these models:
#
# * https://docs.sqlalchemy.org/en/20/orm/declarative_config.html
# * https://docs.sqlalchemy.org/en/20/orm/relationship_api.html


class User(Base):
    __tablename__ = "user"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(
        index=True, unique=True, nullable=False
    )
    display_name: Mapped[str] = mapped_column(
        nullable=False,
        default=lambda x: x.get_current_parameters()["username"],
    )
    password_hash: Mapped[str] = mapped_column(nullable=False)
    salt: Mapped[str] = mapped_column(nullable=False)
    email: Mapped[str] = mapped_column(default="", nullable=False)
    disabled: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False
    )
    last_login_at: Mapped[datetime | None]

    member_links = relationship(
        "Member", back_populates="user", cascade="all, delete-orphan"
    )
    # optional convenience:
    # projects = relationship("Project", secondary="member", viewonly=True)

    @staticmethod
    def create_password_hash(password: str, salt: str):
        """
        Convenient method for when a new user is created or
        existing user changes its password
        """
        return pyargon2_hash(
            password=password, salt=salt, encoding="b64", variant="id"
        )

    def validate_password(self, password: str) -> bool:
        """
        This method should ony be used once in login /token api
        """
        return self.password_hash == self.create_password_hash(
            password, self.salt
        )


class Member(Base):
    """
    Exists to add a list of `User`s to a `Project`
    """

    __tablename__ = "member"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("project.id"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False
    )
    # idx_uniq_project_user = UniqueConstraint(project_id, user_id)
    __table_args__ = (UniqueConstraint(project_id, user_id),)

    user: Mapped[User] = relationship()
    project: Mapped[Project] = relationship()
    # member_roles: Mapped[list["MemberRole"]] = relationship(
    #     "MemberRole",
    #     primaryjoin="Member.id == MemberRole.role_id",
    #     back_populates="member",
    #     cascade="all, delete-orphan",
    #     passive_deletes=True,
    # )
    # member_roles: Mapped[list[MemberRole]] = relationship(
    #     primaryjoin="Member.user_id==MemberRole.user_id"
    #     # back_populates="member",
    #     # cascade="all, delete-orphan",
    #     # passive_deletes=True
    # )


class Project(Base):
    __tablename__ = "project"  # Organizational Unit in LDAP terms

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[str] = mapped_column(index=True, unique=True)
    name: Mapped[str] = mapped_column(nullable=False)
    description: Mapped[str] = mapped_column(default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False
    )
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("project.id"), nullable=True
    )

    parent: Mapped[Project | None] = relationship(
        "Project", remote_side=[id], back_populates="children"
    )
    members: Mapped[list[User]] = relationship(
        User,
        secondary=Member.__table__,
    )
    roles: Mapped[list[Role]] = relationship("Role")
    children = relationship(
        "Project", back_populates="parent", cascade="all, delete-orphan"
    )
    roles = relationship("Role", back_populates="project")


class MemberRole(Base):
    """
    Assign a role user to a user. Must be managed carefully, because users can be
    removed from `Project` `Member`s
    """

    __tablename__ = "member_role"

    # ToDo: remove this primary key
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )
    role_id: Mapped[int] = mapped_column(ForeignKey("role.id"), nullable=False)

    __table_args__ = (UniqueConstraint(user_id, role_id),)

    role: Mapped[Role] = relationship()
    user: Mapped[User] = relationship()
    # member: Mapped[Member] = relationship()


PermissionsAPI = Literal["", "superadmin", "user"]


class Role(Base):
    """
    Exists to add list of `Role`s to a project.

    Typical role names are 'Developer', 'Manager' and 'Reader'
    """

    __tablename__ = "role"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(nullable=False)
    project_id: Mapped[int] = mapped_column(
        ForeignKey(Project.id), nullable=False
    )
    description: Mapped[str] = mapped_column(nullable=False, default="")
    permissions_api: Mapped[PermissionsAPI] = mapped_column(default="")
    "Access these API calls"
    permissions_git: Mapped[str] = mapped_column(default="")
    permissions_storage: Mapped[str] = mapped_column(default="")
    permissions_extra: Mapped[str] = mapped_column(default="")
    idx_uniq_name_project = UniqueConstraint(name, project_id)

    project: Mapped[Project] = relationship(back_populates="roles")
    users: Mapped[list[User]] = relationship(
        User, secondary=MemberRole.__table__
    )


def auth_for_user_stmt(
    project_id: int,
):
    base = select(Project.id, Project.parent_id).where(
        Project.id == project_id
    )
    cte = base.cte(name="anc", recursive=True)
    cte_alias = cte.alias()
    rec_member = select(Project.id, Project.parent_id).where(
        Project.id == cte_alias.c.parent_id
    )
    cte = cte.union_all(rec_member)
    # stmt = select(Project).join(cte, Project.id == cte.c.id)

    return cte
