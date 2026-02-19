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
from senyai_auth import __version__


class AppSettings(BaseModel, strict=True, frozen=True):
    db_url: str = "sqlite+aiosqlite:///./ldap_test.sqlite"
    # to get a string like this run:
    # openssl rand -hex 32
    secret_key: str
    algorithm: Literal["HS256"] = "HS256"
    access_token_expire_minutes: int = 60 * 24 * 31  # 1 month
    # arguments for `create_async_engine`, for example {"echo": True}
    engine: dict[str, bool | int] = {}

    def create_engine(self):
        """
        Notice: dispose async_engine after usage
        """
        engine_kwargs = self.engine
        if self.db_url.startswith("postgresql+asyncpg://"):
            engine_kwargs: dict[str, str | int] = {
                "pool_size": 10,  # max DB connections in pool
                "max_overflow": 5,  # extra connections beyond pool_size
                "pool_timeout": 30,  # seconds to wait for connection from pool
                "pool_recycle": 1800,  # recycle after 30m to avoid stale conns
                "pool_pre_ping": True,  # test connections before use
                **engine_kwargs,
            }

        async_engine = create_async_engine(self.db_url, **engine_kwargs)
        async_session = sessionmaker[AsyncSession](
            bind=async_engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
        )
        return async_engine, async_session


def get_settings():
    import os

    settings_path = os.getenv("AUTH_API_SETTINGS_PATH", "settings_api.json")
    with open(settings_path) as f:
        return AppSettings.model_validate_json(f.read())


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: AppSettings = app.dependency_overrides.get(
        get_settings, get_settings
    )()
    async_engine, app.state.async_session = settings.create_engine()
    app.state.secret_key = settings.secret_key
    app.state.algorithm = settings.algorithm
    app.state.access_token_expire_minutes = (
        settings.access_token_expire_minutes
    )

    from .db import Base

    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await async_engine.dispose()


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with app.state.async_session() as session:
        yield session


app = FastAPI(
    version=__version__,
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
