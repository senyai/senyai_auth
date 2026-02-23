from __future__ import annotations

import os
import base64
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
    JSON,
    type_coerce,
    TypeDecorator,
)
from enum import IntFlag
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy.orm import load_only


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
    role_id: Mapped[int] = mapped_column(
        ForeignKey("role.id", ondelete="CASCADE"), nullable=False
    )
    idx_uniq_user_role = UniqueConstraint(
        user_id, role_id, name="idx_uniq_user_role"
    )

    role: Mapped[Role] = relationship(foreign_keys=[role_id])
    user: Mapped[User] = relationship(
        foreign_keys=[user_id], back_populates="member_roles"
    )
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
    email: Mapped[str] = mapped_column(nullable=False, unique=True)
    contacts: Mapped[str] = mapped_column(
        default="", nullable=False, deferred=True
    )
    disabled: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False
    )
    last_login_at: Mapped[datetime | None]

    # optional convenience:
    # projects = relationship("Project", secondary="member", viewonly=True)

    member_roles: Mapped[list[MemberRole]] = relationship(
        back_populates="user", passive_deletes=True
    )

    @staticmethod
    def make_salt() -> str:
        return base64.b85encode(os.urandom(16)).decode()

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

    def update_password(self, password: str) -> None:
        new_salt = User.make_salt()
        new_password_hash = self.create_password_hash(password, new_salt)
        self.salt = new_salt
        self.password_hash = new_password_hash

    def __repr__(self) -> str:
        return f"{super().__repr__()[:-1]} username={self.username!r}>"


class Member(Base):
    """
    Exists to add a list of `User`s to a `Project`
    """

    __tablename__ = "member"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("project.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey(User.id, ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False
    )
    idx_uniq_project_user = UniqueConstraint(
        project_id, user_id, name="idx_uniq_project_user"
    )

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
        ForeignKey("project.id", ondelete="CASCADE"), nullable=True
    )

    parent: Mapped[Project | None] = relationship(
        remote_side=[id], back_populates="children"
    )
    members: Mapped[list[User]] = relationship(
        User,
        secondary=Member.__table__,
        overlaps="user,project",
    )
    children: Mapped[list[Project]] = relationship(back_populates="parent")
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
        ForeignKey(Project.id, ondelete="CASCADE"), nullable=False
    )
    description: Mapped[str] = mapped_column(nullable=False, default="")
    permissions_api: Mapped[PermissionsAPI] = mapped_column(
        PermissionsAPIType, default=PermissionsAPI.none
    )
    "Access these API calls"
    permissions_git: Mapped[str] = mapped_column(default="")
    permissions_storage: Mapped[str] = mapped_column(default="")
    permissions_extra: Mapped[str] = mapped_column(default="")
    idx_uniq_name_project = UniqueConstraint(
        name, project_id, name="idx_uniq_name_project"
    )

    project: Mapped[Project] = relationship(back_populates="roles")

    members: Mapped[list[User]] = relationship(
        User,
        secondary=MemberRole.__table__,
        overlaps="member_roles,user,role",
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
    roles: Mapped[list[str]] = mapped_column(
        JSON, nullable=False
    )  # json serialized list
    inviter_id: Mapped[User] = mapped_column(
        ForeignKey(User.id, ondelete="CASCADE"), nullable=False
    )
    prompt: Mapped[str] = mapped_column(nullable=False)
    default_username: Mapped[str] = mapped_column(nullable=False)
    default_display_name: Mapped[str] = mapped_column(nullable=False)
    default_email: Mapped[str] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False
    )
    who_accepted_id: Mapped[int | None] = mapped_column(
        ForeignKey(User.id, ondelete="SET NULL"), nullable=True
    )

    who_accepted: Mapped[User | None] = relationship(
        foreign_keys=[who_accepted_id]
    )
    inviter: Mapped[User] = relationship(foreign_keys=[inviter_id])
    project: Mapped[Project] = relationship(foreign_keys=[project_id])


def _create_auth_for_project_stmt():
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


def _create_permissions_api_stmt():
    """
    For `user_id` aggregate sum(Role.permissions_api)
    """
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


def _create_permissions_stmt(field: InstrumentedAttribute[str]):
    """
    Find all Roles that the users is in and aggregate specified Role's `fiend`
    using '|' delimiter

    :param field: Field of a `Role` class
    """
    user_id = bindparam("user_id", type_=Integer)
    return (
        select(
            func.aggregate_strings(field, "|"),
        )
        .join(MemberRole, MemberRole.role_id == Role.id)
        .where(MemberRole.user_id == user_id, field != "")
    )


def _create_list_projects_stmt():
    """
    For a user `user_id` recursively select all users's projects
    """
    user_id = bindparam("user_id", type_=Integer)
    id_name_parent = select(
        Project.id, Project.name, Project.display_name, Project.parent_id
    )
    base = (
        id_name_parent.join(Role, Role.project_id == Project.id)
        .join(MemberRole, MemberRole.role_id == Role.id)
        .where(user_id == MemberRole.user_id)
        .cte(name="base", recursive=True)
    )
    return select(
        base.union_all(
            id_name_parent.join(base, Project.parent_id == base.c.id),
        )
    )


def _create_get_user_by_username_stmt():
    """
    Use session to get user by `username`

    Disabled users will be returned too, and for disabled user an error
    'User is not available anymore' will be shown
    """
    username = bindparam("username", type_=String)
    return (
        select(User)
        .where(User.username == username)
        .options(
            load_only(
                User.id,
                User.username,
                User.password_hash,
                User.salt,
                User.disabled,
            )
        )
    )


def _create_get_user_by_username_or_email_stmt():
    username_or_email = bindparam("username_or_email", type_=String)
    return (
        select(User)
        .where(
            (
                (User.username == username_or_email)
                | (User.email == username_or_email)
            )
        )
        .options(
            load_only(User.id, User.username, User.display_name, User.email)
        )
    )


def _create_get_all_users_for_domain(field: InstrumentedAttribute[str]):
    """
    This is expected to be a scan function
    """
    return (
        select(
            User.username,
            User.display_name,
            User.email,
            func.aggregate_strings(field, "|"),
        )
        .join(MemberRole, MemberRole.user_id == User.id)
        .join(Role, MemberRole.role_id == Role.id)
        .where(field != "", ~User.disabled)
        .group_by(User.username, User.display_name, User.email)
    )


auth_for_project_stmt = _create_auth_for_project_stmt()
permissions_api_stmt = _create_permissions_api_stmt()

permissions_extra_stmt = _create_permissions_stmt(Role.permissions_extra)
permissions_storage_stmt = _create_permissions_stmt(Role.permissions_storage)
permissions_git_stmt = _create_permissions_stmt(Role.permissions_git)
all_users_extra_stmt = _create_get_all_users_for_domain(Role.permissions_extra)
all_users_storage_stmt = _create_get_all_users_for_domain(
    Role.permissions_storage
)
all_users_git_stmt = _create_get_all_users_for_domain(Role.permissions_git)

list_projects_stmt = _create_list_projects_stmt()
get_user_by_username_stmt = _create_get_user_by_username_stmt()
get_user_by_username_or_email_stmt = (
    _create_get_user_by_username_or_email_stmt()
)
select_userid_by_username_stmt = select(User.id).where(
    User.username == bindparam("username", type_=String)
)
