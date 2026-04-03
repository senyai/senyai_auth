from enum import IntEnum


class PermissionsAPI(IntEnum):
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
