from __future__ import annotations
import json


class Permissions:
    NONE = 0
    USER = 1
    """
    * Change password
    * Change display_name
    * List projects
    """
    MANAGER = 2
    """
    * Create and edit roles
    * Manage users
    * Send invites
    """

    ADMIN = 4
    """
    * Create projects
    """
    SUPERADMIN = 8

    api_options: list[dict[str, str | int]] = [
        {"name": "none", "value": 0},
        {"name": "user", "value": 1},
        {"name": "manager", "value": 2},
        {"name": "admin", "value": 4},
    ]


class HXTrigger:
    def __init__(self):
        self.events: dict = {}

    def add_success_event(self, message: str):
        self.events["successEvent"] = {"message": message}

    def add_error_event(self, errors: list):
        self.events["errorEvent"] = {"errors": errors}

    def add_update_projects_tree(self):
        self.events["updateProjects"] = {}

    def add_update_project_info(self):
        self.events["updateProjectInfo"] = {}

    def build(self):
        return self._build(self.events)

    @classmethod
    def _build(cls, events):
        return {"HX-Trigger": json.dumps(events)}

    @classmethod
    def send_errors(cls, response):
        errors = parse_errors(response.json())
        events = {"errorEvent": {"errors": errors}}
        return cls._build(events)


def parse_errors(msg: dict):
    detail = msg.get("detail")
    result = []
    if isinstance(detail, list):
        for d in detail:
            result.append(str(d))
        return result
    return [detail]


def parse_projects(projects: list[dict]):
    def rec_leaf(project):
        if project["parent"] not in idxs:
            if project["id"] in to_check:
                project["children"] = []
                trees.append(project)
                to_check.remove(project["id"])
        else:
            parent = projects[idxs.index(project["parent"])]

            if parent["id"] in to_check:
                rec_leaf(parent)

            if project["id"] in to_check:
                project["children"] = []
                parent["children"].append(project)
                to_check.remove(project["id"])

        return

    idxs = [project["id"] for project in projects]
    to_check = idxs[:]
    trees = []

    while to_check:
        project = next(filter(lambda x: x["id"] == to_check[0], projects))
        rec_leaf(project)

    return trees
