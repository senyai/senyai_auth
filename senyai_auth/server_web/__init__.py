from __future__ import annotations
from quart import (
    Quart,
    render_template,
    redirect,
    url_for,
    request,
    make_response,
)
import httpx
import json

from .. import __version__

from .helpers import Permissions, HXTrigger, parse_projects, parse_errors


class App(Quart):
    client: httpx.AsyncClient


app = App(__name__)

API_HOST = "http://127.0.0.1:8000"


@app.before_serving
async def startup():
    print("create httpx client")
    app.client = httpx.AsyncClient(base_url=API_HOST)


@app.after_serving
async def shutdown():
    await app.client.aclose()
    print("close httpx client")


@app.errorhandler(httpx.NetworkError)
async def handle_connect_error(error: httpx.NetworkError):
    return "", 503


@app.context_processor
async def inject_auth():
    return {
        "has_auth": "Authorization" in request.cookies,
        "version": __version__,
    }


def get_authorization_str(token_type: str, access_token: str):
    return f"{token_type.capitalize()} {access_token}"


@app.get("/")
async def index():
    if token := request.cookies.get("Authorization"):
        user_res = await app.client.get(
            "/ui/main",
            headers={"Authorization": token},
        )
        if user_res.status_code == 200:
            data = user_res.json()
            user = data["user"]
            projects = data["projects"]
            return await render_template(
                "user.html", user=user, projects=parse_projects(projects)
            )
    resp = await make_response(await render_template("login.html"))
    resp.set_cookie("Authorization", "")
    return resp


@app.post("/")
async def login():
    form = await request.form
    api_resp = await app.client.post("/token", data=dict(form))
    if api_resp.status_code == 200:
        token = api_resp.json()
        resp = await make_response("", 200)
        resp.set_cookie(
            "Authorization",
            get_authorization_str(token["token_type"], token["access_token"]),
        )
        resp.headers["HX-Redirect"] = url_for("index")
        return resp
    return ("", api_resp.status_code, HXTrigger.send_errors(api_resp))


@app.route("/logout")
async def logout():
    resp = await make_response(redirect(url_for("index")))
    resp.delete_cookie("Authorization")
    return resp


@app.get("/invites_table")
async def invites_table():
    project_id = request.args.get("project_id", type=int)
    project_name = request.args.get("project_name")
    resp = await app.client.get(
        f"/invites/{project_id}",
        headers={"Authorization": request.cookies.get("Authorization", "")},
    )
    if resp.status_code == 200:
        return await render_template(
            "partials/invites_table.html",
            invites=resp.json(),
            project_id=project_id,
            project_name=project_name,
        )
    return "", resp.status_code, HXTrigger.send_errors(resp)


@app.get("/invite")
async def invite():
    project_id = request.args.get("project_id", type=int)
    project_name = request.args.get("project_name")
    return await render_template(
        "forms/invite_form.html",
        project_id=project_id,
        project_name=project_name,
    )


@app.post("/invite")
async def invite_new():
    form = await request.form
    data = dict(form)
    data["roles"] = []
    resp = await app.client.post(
        "/invite",
        headers={"Authorization": request.cookies.get("Authorization", "")},
        json=data,
    )
    if resp.status_code == 201:
        trigger = HXTrigger()
        url = resp.json()
        trigger.add_update_project_info()
        trigger.add_success_event("Invite created!")
        return (
            await render_template(
                "invite_result.html", url_key=url["url_key"]
            ),
            201,
            trigger.build(),
        )
    return "", resp.status_code, HXTrigger.send_errors(resp)


@app.get("/register/<key>")
async def register(key: str):
    form_res = await app.client.get(f"/invite/{key}")
    form = form_res.json()
    if form_res.status_code == 200:
        return await render_template("register.html", form=form, key=key)
    return form, 404


@app.post("/register/<key>")
async def register_post(key: str):
    form = await request.form
    api_resp = await app.client.post("/register/{key}", json=dict(form))
    if api_resp.status_code == 201:
        resp = await make_response("", 201)
        resp.headers["HX-Redirect"] = url_for("index")
        return resp
    return ("", api_resp.status_code, HXTrigger.send_errors(api_resp))


@app.get("/project/<project_id>")
async def project(project_id: int):
    token = request.cookies.get("Authorization", "")
    resp = await app.client.get(
        f"{API_HOST}/ui/project/{project_id}",
        headers={"Authorization": token},
    )
    if resp.status_code == 200:
        project_info = resp.json()
        permission = project_info.get("permission", 0)

        context = {
            "members": project_info.get("members"),
            "roles": project_info.get("roles"),
            "display_name": project_info.get("display_name"),
            "project_name": project_info.get("name"),
            "can_user": permission >= Permissions.USER,
            "can_manager": permission >= Permissions.MANAGER,
            "can_admin": permission >= Permissions.ADMIN,
            "project_id": int(project_id),
            "description": project_info.get("description"),
            "parent_id": project_info.get("parent_id"),
            "project_id": project_id,
        }

        return await render_template(
            "includes/project_info.html", context=context
        )

    return "", resp.status_code, HXTrigger.send_errors(resp)


@app.post("/project")
async def create_project():
    form = await request.form
    resp = await app.client.post(
        "/project",
        json=dict(form),
        headers={"Authorization": request.cookies.get("Authorization", "")},
    )
    if resp.status_code == 201:
        trigger = HXTrigger()
        trigger.add_update_projects_tree()
        trigger.add_success_event("Project created!")
        trigger.add_close_modal_event()
        return ("", 201, trigger.build())
    return ("", resp.status_code, HXTrigger.send_errors(resp))


@app.patch("/project/<project_id>")
async def update_project(project_id: str):
    form = await request.form
    resp = await app.client.patch(
        f"/project/{project_id}",
        json=dict(form),
        headers={"Authorization": request.cookies.get("Authorization", "")},
    )
    if resp.status_code == 204:
        trigger = HXTrigger()
        trigger.add_update_project_info()
        trigger.add_success_event("Project updated!")
        trigger.add_close_modal_event()
        return "", resp.status_code, trigger.build()
    return "", resp.status_code, HXTrigger.send_errors(resp)


@app.get("/role")
async def role():
    project_id = request.args.get("project_id", 0, type=int)
    return await render_template(
        "forms/upsert_role_form.html",
        form={},
        project_id=project_id,
        api_options=Permissions.api_options,
    )


@app.post("/role")
async def role_new():
    form = await request.form
    data = dict(form)

    resp = await app.client.post(
        "/role",
        headers={"Authorization": request.cookies.get("Authorization", "")},
        json=data,
    )
    if resp.status_code == 201:
        trigger = HXTrigger()
        trigger.add_success_event("Role created!")
        trigger.add_update_project_info()
        trigger.add_close_modal_event()
        return ("", 201, trigger.build())
    return "", resp.status_code, HXTrigger.send_errors(resp)


@app.post("/roles/<user_id>")
async def manage_roles(user_id):
    user_id = int(user_id)
    form = await request.form
    roles = json.loads(form.get("roles", {}))
    added = roles.get("added")
    removed = roles["removed"]

    trigger = HXTrigger()
    cnt = 0
    for role_id in added:
        resp = await app.client.post(
            f"/role/{role_id}/users",
            json=[user_id],
            headers={
                "Authorization": request.cookies.get("Authorization", "")
            },
        )
        if resp.status_code == 201:
            cnt += 1
        else:
            trigger.add_error_event(parse_errors(resp.json()))
    trigger.add_success_event(f"{cnt} roles added!")

    cnt = 0
    for role_id in removed:
        resp = await app.client.request(
            "DELETE",
            f"/role/{role_id}/users",
            json=[user_id],
            headers={
                "Authorization": request.cookies.get("Authorization", "")
            },
        )
        if resp.status_code == 204:
            cnt += 1
        else:
            trigger.add_error_event(parse_errors(resp.json()))
    trigger.add_success_event(f"{cnt} roles removed!")
    trigger.add_update_project_info()

    trigger.add_close_modal_event()
    return "", 201, trigger.build()


@app.get("/forms/new_project/<parent_id>")
async def get_new_project_form(parent_id: str):
    context = {"parent_id": parent_id}
    return await render_template(
        "forms/upsert_project_form.html", context=context
    )


@app.get("/forms/edit_project/<project_id>")
async def get_edit_project_form(project_id: str):
    resp = await app.client.get(
        f"/project/{project_id}",
        headers={"Authorization": request.cookies.get("Authorization", "")},
    )
    if resp.status_code == 200:
        context = {"project_id": project_id, **resp.json()}
        return await render_template(
            "forms/upsert_project_form.html", context=context, edit_mode=True
        )
    return "", resp.status_code, HXTrigger.send_errors(resp)


@app.get("/forms/manage_user_roles")
async def get_manage_user_roles_form():
    user_id = request.args.get("user_id", type=int)
    project_id = request.args.get("project_id", type=int)
    resp = await app.client.get(
        f"ui/project/{project_id}",
        headers={"Authorization": request.cookies.get("Authorization", "")},
    )
    if resp.status_code == 200:
        data = resp.json()
        user = next(filter(lambda x: x["id"] == user_id, data["members"]))
        context = {"user": user, "roles": data["roles"]}
        return await render_template(
            "forms/manage_user_roles_form.html", context=context
        )
    return "", resp.status_code, HXTrigger.send_errors(resp)


@app.get("/forms/change_password")
async def get_change_password_form():
    user_id = request.args.get("user_id", type=int)
    return await render_template("forms/update_user_form.html", user_id=user_id)


@app.patch("/change_password")
async def change_password():
    return ""