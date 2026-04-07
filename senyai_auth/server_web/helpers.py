from __future__ import annotations
from typing import TypedDict, NotRequired
import json
from collections import defaultdict
from ..server_api.permissions import PermissionsAPI


API_OPTIONS: list[dict[str, str | int]] = [
    {"name": "none", "value": PermissionsAPI.none},
    {"name": "user", "value": PermissionsAPI.user},
    {"name": "manager", "value": PermissionsAPI.manager},
    {"name": "admin", "value": PermissionsAPI.admin},
    {"name": "superadmin", "value": PermissionsAPI.superadmin},
]


class HXTrigger:
    def __init__(self):
        self.events: dict[str, dict[str, list[str]]] = defaultdict(
            lambda: defaultdict(list)
        )

    def add_success_event(self, message: str):
        self.events["successEvent"]["message"].append(message)

    def add_error_event(self, errors: list[str]):
        self.events["errorEvent"]["errors"].extend(errors)

    def add_update_projects_tree(self):
        self.events["updateProjects"] = {}

    def add_update_project_info(self):
        self.events["updateProjectInfo"] = {}

    def add_close_modal_event(self):
        self.events["closeModal"] = {}

    def add_update_invites_tab(self):
        self.events["updateInvitesTab"] = {}

    def build(self):
        return self._build(self.events)

    @classmethod
    def _build(cls, events: dict[str, dict[str, list[str]]]):
        return {"HX-Trigger": json.dumps(events)}


def parse_errors(msg: dict[str, str | list[str]]):
    detail = msg.get("detail")
    result: list[str] = []
    if isinstance(detail, list):
        for d in detail:
            result.append(str(d))
        return result
    return [detail]


class ProjectInfo(TypedDict):
    id: int
    name: str
    display_name: str
    parent: int | None
    children: NotRequired[list["ProjectInfo"]]


def parse_projects(projects: list[ProjectInfo]) -> list[ProjectInfo]:
    all_projects = {project["id"]: project for project in projects}
    root_projects: list[ProjectInfo] = []
    for project in projects:
        parent_id = project["parent"]
        if parent_id in all_projects:
            parent = all_projects[parent_id]
            if "children" not in parent:
                parent["children"] = [project]
            else:
                parent["children"].append(project)
        else:
            root_projects.append(project)
    return root_projects
