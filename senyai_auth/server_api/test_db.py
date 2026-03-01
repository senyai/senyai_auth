from __future__ import annotations
from unittest import IsolatedAsyncioTestCase
from sqlalchemy import select, func
from . import AppSettings
from .db import Project, Role, User, Base, Member, MemberRole


def _test_get_settings():
    return AppSettings(
        db_url="sqlite+aiosqlite:///:memory:",
        secret_key="debug_" * 6,
        engine={"echo": False},
    )


MEMBERS_PER_ROLE_STMT = (
    select(Role.id, func.count())
    .select_from(Role)
    .join(MemberRole, MemberRole.role_id == Role.id)
    .group_by(Role.id)
    .order_by(Role.id)
)


class IntegrityTest(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        settings = _test_get_settings()
        self.async_engine, self.async_session = settings.create_engine()
        async with self.async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await self.initDb()

    async def asyncTearDown(self):
        await self.async_engine.dispose()

    async def initDb(self):
        self.project1 = project1 = Project(name="p1", display_name="p1")
        self.project2 = project2 = Project(name="p2", display_name="p2")
        user1 = User(
            username="user1", password_hash="a", salt="e", email="a@j.c"
        )
        user2 = User(
            username="user2", password_hash="b", salt="f", email="b@j.c"
        )
        user3 = User(
            username="user3", password_hash="c", salt="g", email="c@j.c"
        )
        user4 = User(
            username="user4", password_hash="d", salt="h", email="d@j.c"
        )
        async with self.async_session() as session:
            session.add_all((user1, user2, user3, user4, project1, project2))
            self.p1_r1 = p1_r1 = Role(project=project1, name="p1_r1")
            self.p1_r2 = p1_r2 = Role(project=project1, name="p1_r2")
            self.p2_r1 = p2_r1 = Role(project=project2, name="p2_r1")
            self.p2_r2 = p2_r2 = Role(project=project2, name="p2_r2")
            session.add_all((p1_r1, p1_r2, p2_r1, p2_r2))
            project1.members.extend((user1, user2, user3))
            project2.members.extend((user2, user3, user4))
            p1_r1.members.extend((user1, user2))
            p1_r2.members.extend((user3,))
            p2_r1.members.extend((user2, user3))
            p2_r2.members.extend((user2, user4))

            await session.commit()

    async def test_delete_role(self):
        """
        Deleting a role must also delete its members
        """
        async with self.async_session() as session:
            role_members = tuple(await session.execute(MEMBERS_PER_ROLE_STMT))
            self.assertEqual(role_members, ((1, 2), (2, 1), (3, 2), (4, 2)))
            await session.delete(self.p1_r1)
            await session.delete(self.p2_r2)
            await session.flush((self.p1_r1, self.p2_r2))
            role_members = tuple(await session.execute(MEMBERS_PER_ROLE_STMT))
            self.assertEqual(role_members, ((2, 1), (3, 2)))
            await session.rollback()

    async def test_delete_project(self):
        """
        Deleting a project must also delete its roles and members
        """
        ROLES_PER_PROJECT_STMT = (
            select(Project.id, func.count())
            .select_from(Project)
            .join(Role, Role.project_id == Project.id)
            .group_by(Project.id)
            .order_by(Project.id)
        )
        async with self.async_session() as session:
            role_members = tuple(await session.execute(ROLES_PER_PROJECT_STMT))
            self.assertEqual(role_members, ((1, 2), (2, 2)))
            await session.delete(self.project1)
            await session.flush()
            role_members = tuple(await session.execute(ROLES_PER_PROJECT_STMT))
            self.assertEqual(role_members, ((2, 2),))

            role_members = tuple(await session.execute(MEMBERS_PER_ROLE_STMT))
            self.assertEqual(role_members, ((3, 2), (4, 2)))

            await session.rollback()
