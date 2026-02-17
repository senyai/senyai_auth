from __future__ import annotations
from typing import Annotated, TypedDict, cast
from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from . import app
from .. import get_async_session
from ..db import User, get_user_by_username_stmt
from .exceptions import response_description
from sqlalchemy.ext.asyncio import AsyncSession

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class Token(BaseModel, strict=True, frozen=True):
    access_token: str
    token_type: str


class TokenData(TypedDict):
    username: str
    salt: str  # defense against user password change
    exp: datetime


def _create_access_token(
    username: str, expires_delta: timedelta, salt: str
) -> str:
    to_encode: TokenData = {
        "username": username,
        "exp": datetime.now(timezone.utc) + expires_delta,
        "salt": salt,
    }
    encoded_jwt = jwt.encode(
        to_encode, app.state.secret_key, algorithm=app.state.algorithm
    )
    return encoded_jwt


async def _get_user_by_username(
    username: str, session: AsyncSession
) -> User | None:
    return await session.scalar(
        get_user_by_username_stmt, params={"username": username}
    )


async def authenticate_user(
    username: str, password: str, session: AsyncSession
) -> User | None:
    user = await _get_user_by_username(username, session)
    if not user:
        return
    if not user.validate_password(password):
        return
    return user


@app.post(
    "/token",
    response_model=Token,
    tags=["auth"],
    responses={
        status.HTTP_401_UNAUTHORIZED: response_description(
            "Incorrect username or password"
        )
    },
)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: AsyncSession = Depends(get_async_session),
) -> Token:
    user = await authenticate_user(
        form_data.username, form_data.password, session
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(
        minutes=app.state.access_token_expire_minutes
    )
    access_token = _create_access_token(
        username=user.username,
        expires_delta=access_token_expires,
        salt=user.salt,
    )
    return Token(access_token=access_token, token_type="bearer")


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: AsyncSession = Depends(get_async_session),
) -> User:
    try:
        payload = cast(
            TokenData,
            jwt.decode(
                token, app.state.secret_key, algorithms=[app.state.algorithm]
            ),
        )
    except InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # we must fetch user on every request, because user information update
    user = await _get_user_by_username(payload["username"], session)
    # we must check salt because user password can change
    if user is None or user.salt != payload["salt"] or user.disabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not available anymore",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
