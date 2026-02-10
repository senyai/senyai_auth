from __future__ import annotations
from quart import (
    Quart,
    render_template,
    redirect,
    url_for,
    request,
    # session,
    # abort,
    make_response,
)
import httpx
import json

# from functools import wraps
# import secrets
from .forms import (
    InviteFormHTML,
    RegisterFormHTML,
    LoginForm,
    RoleForm,
    RoleManageData,
)

app = Quart(__name__)
# app.secret_key = "flGsgDGgukHFyuK"

API_HOST = "http://127.0.0.1:8000"


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

    api_options = [
        {"name": "none", "value": 0},
        {"name": "user", "value": 1},
        {"name": "manager", "value": 2},
        {"name": "admin", "value": 4},
    ]


def parse_errors(msg: dict):
    detail = msg.get("detail")
    result = set()
    if isinstance(detail, list):
        for d in detail:
            if "msg" in d:
                result.add(d.get("msg"))
        return result
    return {detail}


# def parse_projects():


@app.errorhandler(httpx.ConnectError)
async def handle_connect_error(error):
    return "", 503


@app.context_processor
async def inject_auth():
    return {"is_auth": request.cookies.get("Authorization", False)}


def get_authorization_str(token_type, access_token):
    return f"{token_type.capitalize()} {access_token}"


@app.get("/")
async def index():
    if token := request.cookies.get("Authorization"):
        async with httpx.AsyncClient() as client:
            user_res = await client.get(
                f"{API_HOST}/ui/main",
                headers={"Authorization": token},
            )
        if user_res.status_code == 200:
            data = user_res.json()
            user = data["user"]
            projects = data["projects"]
            return await render_template(
                "user.html", user=user, projects=projects
            )
    resp = await make_response(await render_template("login.html"))
    resp.set_cookie("Authorization", "")
    return resp


@app.post("/")
async def login():
    errors = {}
    form = await request.form
    data, errors = LoginForm.parse_form(dict(form))
    if data:
        async with httpx.AsyncClient() as client:
            token_res = await client.post(
                f"{API_HOST}/token", data=data.model_dump()
            )
        token = token_res.json()
        if token_res.status_code == 200:
            resp = await make_response(redirect(url_for("index")))
            resp.set_cookie(
                "Authorization",
                get_authorization_str(
                    token["token_type"], token["access_token"]
                ),
            )
            return resp
            # errors = token.get("detail")
        errors = parse_errors(token)
    return await render_template("login.html", errors=errors), 400


@app.route("/logout")
# @login_required
async def logout():
    resp = await make_response(redirect(url_for("index")))
    resp.set_cookie("Authorization", "")
    return resp


@app.get("/invites_table")
async def invites_table_get():
    project_id = request.args.get("project_id")
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{API_HOST}/invites/{project_id}",
            headers={
                "Authorization": request.cookies.get("Authorization", "")
            },
        )
    if resp.status_code == 200:
        return await render_template(
            "partials/invites_table.html", invites=resp.json()
        )
    return await render_template(
        "includes/toasts.html", errors=parse_errors(resp.json())
    )


@app.get("/invite")
async def invite_get():
    project_id = request.args.get("project_id")
    project_name = request.args.get("project_name")
    return await render_template(
        "forms/invite_form.html",
        project_id=project_id,
        project_name=project_name,
    )


@app.post("/invite")
async def invite_post():
    form = await request.form
    data, errors = InviteFormHTML.parse_form(dict(form))
    if data:
        async with httpx.AsyncClient() as client:
            url_res = await client.post(
                f"{API_HOST}/invite",
                headers={
                    "Authorization": request.cookies.get("Authorization", "")
                },
                json=data.to_api().model_dump(),
            )
        url = url_res.json()
        if url_res.status_code == 201:
            return (
                await render_template(
                    "invite_result.html", url_key=url["url_key"]
                ),
                201,
                {
                    "HX-Trigger": json.dumps(
                        {
                            "objectCreated": {},
                        }
                    )
                },
            )
        errors = url["detail"]
    print(errors)
    return (
        await render_template(
            "includes/toasts.html", form=form, errors=errors
        ),
        400,
    )


@app.get("/register/<key>")
async def use_invite_get(key: str):
    async with httpx.AsyncClient() as client:
        form_res = await client.get(f"{API_HOST}/invite/{key}")
    form = form_res.json()
    if form_res.status_code == 200:
        # generate_csrf()
        return await render_template("register.html", form=form, errors={})
    return form


@app.post("/register/<key>")
async def use_invite_post(key: str):
    form = await request.form
    # await check_csrf(form)
    data, errors = RegisterFormHTML.parse_form(form)
    if data:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{API_HOST}/register/{key}", json=data.to_api().model_dump()
            )
        if resp.status_code == 201:
            return redirect(url_for("index"))
        errors = parse_errors(resp.json())
    return await render_template("register.html", form=form, errors=errors)


@app.get("/project/<project_id>")
async def project_get(project_id: int):
    token = request.cookies.get("Authorization", "")
    headers = request.headers
    # print(headers)
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{API_HOST}/ui/project/{project_id}",
            headers={"Authorization": token},
        )
    project_info = resp.json()
    if resp.status_code == 200:
        members = project_info.get("members")
        roles = project_info.get("roles")
        permission = project_info.get("permission")
        can_user = permission >= Permissions.USER
        can_manager = permission >= Permissions.MANAGER
        can_admin = permission >= Permissions.ADMIN
        return await render_template(
            "includes/project_info.html",
            members=members,
            roles=roles,
            project_id=project_id,
            can_user=can_user,
            can_manager=can_manager,
            can_admin=can_admin,
        )
    return await render_template(
        "includes/toasts.html", errors=parse_errors(project_info)
    )


@app.get("/role")
async def role_get():
    project_id = request.args.get("project_id", 0)
    return await render_template(
        "forms/upsert_role_form.html",
        form={},
        project_id=project_id,
        api_options=Permissions.api_options,
    )


@app.post("/role")
async def role_post():
    form = await request.form

    data, errors = RoleForm.parse_form(dict(form))

    if data:
        async with httpx.AsyncClient() as client:
            res = await client.post(
                f"{API_HOST}/role",
                headers={
                    "Authorization": request.cookies.get("Authorization", "")
                },
                json=data.model_dump(),
            )
        if res.status_code == 201:
            return (
                "",
                201,
                {
                    "HX-Trigger": json.dumps(
                        {
                            "objectCreated": {},
                            "successEvent": {"message": "Role created"},
                        }
                    )
                },
            )
        errors = parse_errors(res.json())
        # print(res.json())
    return (
        await render_template(
            "forms/upsert_role_form.html",
            form=form,
            project_id=form.get("project_id", 0),
            api_options=Permissions.api_options,
            errors=errors,
        ),
        400,
    )


@app.get("/role_manage_form")
async def manage_role_form():
    # form = request.args
    print(request.args)

    # data, errors = RoleManageData.parse_form(form)
    return await render_template("forms/add_roles_form.html")
