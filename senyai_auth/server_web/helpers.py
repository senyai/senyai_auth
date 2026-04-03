from __future__ import annotations
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
