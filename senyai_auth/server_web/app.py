from __future__ import annotations
from quart import Quart, render_template, redirect, url_for, request, session
import httpx


app = Quart(__name__)
app.secret_key = "flGsgDGgukHFyuK"


def get_authorization_str(token_type, access_token):
    return f"{token_type.capitalize()} {access_token}"


@app.get("/")
async def index():
    if session["Authorization"]:
        async with httpx.AsyncClient() as client:
            user_res = await client.get(
                "http://127.0.0.1:8000/user",
                headers={"Authorization": session["Authorization"]},
            )
            if user_res.status_code == 200:
                return await render_template("user.html", data=user_res.json())
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
            return redirect(url_for("user"))
        error = token.get("detail")
    return await render_template("login.html", error=error)



app.run()
