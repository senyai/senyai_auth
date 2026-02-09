from __future__ import annotations
from typing import Literal, AsyncGenerator
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request
from starlette.responses import HTMLResponse


class AppSettings(BaseModel, strict=True, frozen=True):
    db_url: str = "sqlite+aiosqlite:///./ldap_test.sqlite"
    # to get a string like this run:
    # openssl rand -hex 32
    secret_key: str
    algorithm: Literal["HS256"] = "HS256"
    access_token_expire_minutes: int = 60 * 24 * 31  # 1 month
    echo: bool = False


def get_settings():
    import os

    settings_path = os.getenv("SENYAI_AUTH_SETTINGS_PATH", "settings.json")
    with open(settings_path) as f:
        return AppSettings.model_validate_json(f.read())


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = app.dependency_overrides.get(get_settings, get_settings)()
    async_engine = create_async_engine(settings.db_url, echo=settings.echo)
    app.state.async_session = sessionmaker[AsyncSession](
        async_engine, class_=AsyncSession, expire_on_commit=False
    )
    app.state.secret_key = settings.secret_key
    app.state.algorithm = settings.algorithm
    app.state.access_token_expire_minutes = (
        settings.access_token_expire_minutes
    )

    from .db import Base

    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with app.state.async_session() as session:
        yield session


app = FastAPI(
    version="0.1.1",
    title="Senyai Auth API",
    contact={
        "name": "Arseniy Terekhin",
        "url": "https://github.com/senyai/senyai_auth",
        "email": "senyai@gmail.com",
    },
    lifespan=lifespan,
    docs_url=None,
)
app.mount(
    "/static",
    StaticFiles(directory=__file__[: -len("__init__.py")] + "static"),
    name="static",
)


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html(req: Request) -> HTMLResponse:
    root_path = req.scope.get("root_path", "").rstrip("/")
    openapi_url = root_path + app.openapi_url
    oauth2_redirect_url = app.swagger_ui_oauth2_redirect_url
    if oauth2_redirect_url:
        oauth2_redirect_url = root_path + oauth2_redirect_url
    return get_swagger_ui_html(
        openapi_url=openapi_url,
        title=f"{app.title} - Swagger UI",
        oauth2_redirect_url=oauth2_redirect_url,
        init_oauth=app.swagger_ui_init_oauth,
        swagger_ui_parameters=app.swagger_ui_parameters,
        swagger_js_url="/static/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger-ui.css",
        swagger_favicon_url="/static/favicon.png",
    )


from . import api as api
