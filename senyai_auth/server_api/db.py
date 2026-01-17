from __future__ import annotations

from sqlalchemy import func, ForeignKey, UniqueConstraint
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)
from datetime import datetime
from pyargon2 import hash as pyargon2_hash
from sqlalchemy import (
    bindparam,
    Dialect,
    Integer,
    select,
    String,
    type_coerce,
    TypeDecorator,
)
from enum import IntFlag


class Base(DeclarativeBase):
    pass


#
# What to read to understand how to write these models:
#
# * https://docs.sqlalchemy.org/en/20/orm/declarative_config.html
# * https://docs.sqlalchemy.org/en/20/orm/relationship_api.html


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
    user: Mapped[User] = relationship(back_populates="member_roles")
    # member: Mapped[Member] = relationship()


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

    # optional convenience:
    # projects = relationship("Project", secondary="member", viewonly=True)

    member_roles: Mapped[list[MemberRole]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

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

    def __repr__(self) -> str:
        return f"{super().__repr__()[:-1]} username={self.username!r}>"


class Member(Base):
    """
    Exists to add a list of `User`s to a `Project`
    """

    __tablename__ = "member"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("project.id"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(ForeignKey(User.id), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False
    )
    idx_uniq_project_user = UniqueConstraint(project_id, user_id)

    user: Mapped[User] = relationship(foreign_keys=[user_id])
    project: Mapped[Project] = relationship(foreign_keys=[project_id])


class Project(Base):
    __tablename__ = "project"  # Organizational Unit in LDAP terms

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(index=True, unique=True)
    display_name: Mapped[str] = mapped_column(nullable=False)
    description: Mapped[str] = mapped_column(default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False
    )
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("project.id"), nullable=True
    )

    parent: Mapped[Project | None] = relationship(
        remote_side=[id], back_populates="children"
    )
    members: Mapped[list[User]] = relationship(
        User,
        secondary=Member.__table__,
    )
    roles: Mapped[list[Role]] = relationship("Role")
    children: Mapped[list[Project]] = relationship(
        back_populates="parent", cascade="all, delete-orphan"
    )
    roles: Mapped[list[Role]] = relationship(back_populates="project")

    def __repr__(self) -> str:
        return f"{super().__repr__()[:-1]} project_id={self.name}!r>"


class PermissionsAPI(IntFlag):
    """
    Warning! Do not add or remove elements from this class

    Permissions:
    """

    none = 0

    user = 1
    """
    * Change password
    * Change display_name
    * List projects
    """

    manager = 2
    """
    * Create and edit roles
    * Manage users
    * Send invites
    """

    admin = 4
    """
    * Create projects
    """

    superadmin = 8
    """
    * All, but ideally this permission is never used
    """


class PermissionsAPIType(TypeDecorator[PermissionsAPI]):
    impl = Integer
    cache_ok = True

    def process_bind_param(
        self, value: PermissionsAPI | None, dialect: Dialect
    ) -> int | None:
        return None if value is None else value.value

    def process_result_value(
        self, value: str | int | None, dialect: Dialect
    ) -> PermissionsAPI:
        if value is None:
            return PermissionsAPI.none
        assert isinstance(value, str | int), repr(value)
        return PermissionsAPI(int(value))


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
    permissions_api: Mapped[PermissionsAPI] = mapped_column(
        PermissionsAPIType, default=PermissionsAPI.none
    )
    "Access these API calls"
    permissions_git: Mapped[str] = mapped_column(default="")
    permissions_storage: Mapped[str] = mapped_column(default="")
    permissions_extra: Mapped[str] = mapped_column(default="")
    idx_uniq_name_project = UniqueConstraint(name, project_id)

    project: Mapped[Project] = relationship(back_populates="roles")

    members: Mapped[list[User]] = relationship(
        User,
        secondary=MemberRole.__table__,
    )

    def __repr__(self) -> str:
        return (
            f"{super().__repr__()[:-1]} name={self.name!r} "
            f"api={self.permissions_api!r} "
            f"git={self.permissions_git!r} "
            f"storage={self.permissions_storage!r} "
            f"extra={self.permissions_extra!r} "
        )


class Invitation(Base):
    __tablename__ = "invitation"

    id: Mapped[int] = mapped_column(primary_key=True)
    url_key: Mapped[str] = mapped_column(String(32), unique=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey(Project.id), nullable=False
    )
    inviter_id: Mapped[User] = mapped_column(
        ForeignKey(User.id), nullable=False
    )
    prompt: Mapped[str] = mapped_column(nullable=False)
    default_username: Mapped[str] = mapped_column(nullable=False)
    default_display_name: Mapped[str] = mapped_column(nullable=False)
    default_email: Mapped[str] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False
    )
    who_accepted_id: Mapped[int | None] = mapped_column(
        ForeignKey(User.id), nullable=True
    )

    who_accepted: Mapped[User | None] = relationship(
        foreign_keys=[who_accepted_id]
    )
    inviter: Mapped[User] = relationship(foreign_keys=[inviter_id])
    project: Mapped[Project] = relationship(foreign_keys=[project_id])


def create_auth_for_project_stmt():
    """
    Let's say user wants to add a `Role`. We must ensure he or she have
    permissions. That's the intent of this function.
    """
    project_id = bindparam("project_id", type_=Integer)
    user_id = bindparam("user_id", type_=Integer)
    id_and_parent = select(Project.id, Project.parent_id)
    base = id_and_parent.where(Project.id == project_id).cte(
        name="base", recursive=True
    )
    user_projects = base.union_all(
        id_and_parent.join(base, Project.id == base.c.parent_id),
    )
    return (
        select(
            type_coerce(
                func.sum(func.distinct(Role.permissions_api)),
                PermissionsAPIType,
            )
        )
        .join(user_projects, user_projects.c.id == Role.project_id)
        .join(
            MemberRole,
            (MemberRole.role_id == Role.id) & (MemberRole.user_id == user_id),
        )
    )


def create_all_permissions_stmt():
    user_id = bindparam("user_id", type_=Integer)
    return select(
        type_coerce(
            func.sum(func.distinct(Role.permissions_api)),
            PermissionsAPIType,
        )
    ).join(
        MemberRole,
        (MemberRole.role_id == Role.id) & (MemberRole.user_id == user_id),
    )


auth_for_project_stmt = create_auth_for_project_stmt()
all_permissions_stmt = create_all_permissions_stmt()
