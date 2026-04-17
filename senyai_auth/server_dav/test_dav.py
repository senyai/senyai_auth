from __future__ import annotations
from unittest import TestCase
from . import Permissions, DAVPath


class PermissionsTest(TestCase):
    def test_user_can_only_see_their_folder(self):
        perm = Permissions(["user1"])
        folders = perm.list_children(DAVPath(""))
        self.assertEqual(folders, ["user1"])

    def test_user_have_no_access_to_outside_directory(self):
        perm = Permissions(["user1"])
        folders = perm.list_children(DAVPath("xx"))
        self.assertIsNone(folders)

    def test_duplicate_permissions(self):
        perm = Permissions(
            ["user1", "user1", "user2", "user2:w", "user1:w", "user3", "user3"]
        )
        folders = perm.list_children(DAVPath(""))
        self.assertEqual(folders, ["user1", "user2", "user3"])
        self.assertTrue(perm.has_read_access(DAVPath("user1")))
        self.assertTrue(perm.has_write_access(DAVPath("user1")))
        self.assertTrue(perm.has_read_access(DAVPath("user2")))
        self.assertTrue(perm.has_write_access(DAVPath("user2")))
        self.assertTrue(perm.has_read_access(DAVPath("user3")))
        self.assertFalse(perm.has_write_access(DAVPath("user3")))
