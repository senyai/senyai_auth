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

# from functools import wraps
# import secrets
from .forms import InviteFormHTML, RegisterFormHTML, LoginForm

app = Quart(__name__)
# app.secret_key = "flGsgDGgukHFyuK"

API_HOST = "http://127.0.0.1:8000"


def parse_errors(msg: dict):
    detail = msg.get("detail")
    result = set()
    if isinstance(detail, list):
        for d in detail:
            if "msg" in d:
                result.add(d.get("msg"))
        return result
    return {detail}


# def login_required(view):
#     @wraps(view)
#     async def wrapper(*args, **kwargs):
#         if "Authorization" not in session:
#             return redirect(url_for("login", next=request.url))
#         return await view(*args, **kwargs)

#     return wrapper


# def generate_csrf():
#     session["csrf"] = secrets.token_hex(16)


# async def check_csrf(form):
#     token = form.get("csrf_token")
#     if not token or token != session["csrf"]:
#         abort(403)


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


@app.get("/invite")
# @login_required
async def invite_get():
    # generate_csrf()
    return await render_template("invite.html", form={}, errors={})


@app.post("/invite")
# @login_required
async def invite_post():
    form = await request.form
    # await check_csrf(form)
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
            return await render_template(
                "invite_result.html", url_key=url["url_key"]
            )
        errors = url["detail"]
    return (
        await render_template("invite.html", form=form, errors=errors),
        400,
    )


@app.get("/invite/<key>")
async def use_invite_get(key: str):
    async with httpx.AsyncClient() as client:
        form_res = await client.get(f"{API_HOST}/invite/{key}")
    form = form_res.json()
    if form_res.status_code == 200:
        # generate_csrf()
        return await render_template("register.html", form=form, errors={})
    return form


@app.post("/invite/<key>")
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


app.run()
