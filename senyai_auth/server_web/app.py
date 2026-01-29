from __future__ import annotations
from quart import (
    Quart,
    render_template,
    redirect,
    url_for,
    request,
    session,
    abort,
)
import httpx
from functools import wraps
import secrets
from .forms import InviteForm, RegisterFormHTML, LoginFormHTML


app = Quart(__name__)
app.secret_key = "flGsgDGgukHFyuK"

API_HOST = "http://127.0.0.1:8000"


def login_required(view):
    @wraps(view)
    async def wrapper(*args, **kwargs):
        if "Authorization" not in session:
            return redirect(url_for("login", next=request.url))
        return await view(*args, **kwargs)

    return wrapper


def generate_csrf():
    session["csrf"] = secrets.token_hex(16)


async def check_csrf(form):
    token = form.get("csrf")
    if not token or token != session["csrf"]:
        abort(403)


@app.context_processor
async def inject_auth():
    return {"is_auth": "Authorization" in session}


def get_authorization_str(token_type, access_token):
    return f"{token_type.capitalize()} {access_token}"


@app.get("/")
async def index():
    if "Authorization" in session:
        async with httpx.AsyncClient() as client:
            user_res = await client.get(
                f"{API_HOST}/ui/main",
                headers={"Authorization": session["Authorization"]},
            )
            if user_res.status_code == 200:
                return await render_template("user.html", data=user_res.json())
            session.clear()
    return await render_template("login.html")


@app.post("/")
async def login():
    error = None
    form = await request.form
    params = {
        "username": form.get("username", ""),
        "password": form.get("password", ""),
    }
    async with httpx.AsyncClient() as client:
        token_res = await client.post("{API_HOST}/token", data=params)
        token = token_res.json()
        if token_res.status_code == 200:
            session["Authorization"] = get_authorization_str(
                token["token_type"], token["access_token"]
            )
            return redirect(url_for("index"))
        error = token.get("detail")
    return await render_template("login.html", error=error), 400


@app.route("/logout")
@login_required
async def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/invite")
@login_required
async def invite_get():
    generate_csrf()
    return await render_template(
        "invite.html", csrf=session["csrf"], form={}, errors={}
    )


@app.post("/invite")
@login_required
async def invite_post():
    form = await request.form
    await check_csrf(form)
    data, errors = InviteForm.parse_form(form)

    if data:
        async with httpx.AsyncClient() as client:
            url_res = await client.post(
                f"{API_HOST}/invite",
                headers={"Authorization": session["Authorization"]},
                data=data.model_dump(),
            )
        url = url_res.json()
        if url_res.status_code == 200:
            return await render_template(
                "invite_result.html", url_key=url["url_key"]
            )
        errors = url["detail"]
    return (
        await render_template(
            "invite.html", csrf=session["csrf"], form=form, errors=errors
        ),
        400,
    )


@app.get("/invite/<key>")
async def use_invite_get(key: str):
    async with httpx.AsyncClient() as client:
        form_res = await client.get(f"{API_HOST}/invite/{key}")
    form = form_res.json()
    if form_res.status_code == 200:
        generate_csrf()
        return await render_template(
            "register.html", form=form, csrf=session["csrf"], errors={}
        )
    return form


@app.post("/invite/<key>")
async def use_invite_post(key: str):
    form = await request.form
    await check_csrf(form)
    data, errors = RegisterFormHTML.parse_form(form)
    if data:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{API_HOST}/register/{key}", json=data.to_api().model_dump()
            )
        if resp.status_code == 201:
            return redirect(url_for("index"))
        errors = resp.json()["detail"]

    return await render_template(
        "register.html", form=form, csrf=session["csrf"], errors=errors
    )


app.run()
