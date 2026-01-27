from __future__ import annotations
from quart import Quart, render_template, redirect, url_for, request, session
import httpx
from functools import wraps


app = Quart(__name__)
app.secret_key = "flGsgDGgukHFyuK"


def login_required(view):
    @wraps(view)
    async def wrapper(*args, **kwargs):
        if "Authorization" not in session:
            return redirect(url_for("login", next=request.url))
        return await view(*args, **kwargs)
    return wrapper


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
                "http://127.0.0.1:8000/ui/main",
                headers={"Authorization": session["Authorization"]},
            )
            if user_res.status_code == 200:
                return await render_template("user.html", data=user_res.json())
            return redirect(url_for("logout"))
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
        token_res = await client.post(
            "http://127.0.0.1:8000/token", data=params
        )
        token = token_res.json()
        if token_res.status_code == 200:
            session["Authorization"] = get_authorization_str(
                token["token_type"], token["access_token"]
            )
            return redirect(url_for("index"))
        error = token.get("detail")
    return await render_template("login.html", error=error)


@app.route("/logout")
@login_required
async def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/invite")
@login_required
async def invite_get():
    return await render_template("invite.html")


# @app.post("/invite")
# @login_required
# async def invite_post():

#     form = await request.form
#     params = {"project_id": int(form.get("pro"))}


app.run()
