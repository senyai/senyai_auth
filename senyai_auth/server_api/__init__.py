from __future__ import annotations
from typing import Literal, AsyncGenerator
from contextlib import asynccontextmanager
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker


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
)
from . import api as api
