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
