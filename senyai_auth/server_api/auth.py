from __future__ import annotations
from typing import Annotated, TypedDict, cast
from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from . import app
from .db import User
from sqlalchemy import select


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class Token(BaseModel):
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
    app.state
    encoded_jwt = jwt.encode(
        to_encode, app.state.secret_key, algorithm=app.state.algorithm
    )
    return encoded_jwt


async def _get_user_by_username(username: str) -> User | None:
    stmt = select(User).where(User.username == username)
    async with app.state.async_session() as session:
        user = (await session.execute(stmt)).scalar_one_or_none()
    return user


async def authenticate_user(username: str, password: str) -> User | None:
    user = await _get_user_by_username(username)
    if not user:
        return
    if not user.validate_password(password):
        return
    return user


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> JSONResponse:
    user = await authenticate_user(form_data.username, form_data.password)
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
    token = Token(access_token=access_token, token_type="bearer")
    response = JSONResponse(token.model_dump())
    response.set_cookie(
        key="access_token", value=f"Bearer {access_token}", httponly=True
    )
    return response


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
) -> User:
    try:
        payload = cast(
            TokenData,
            jwt.decode(
                token, app.state.secret_key, algorithms=[app.state.algorithm]
            ),
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # we must fetch user on every request, because user information update
    user = await _get_user_by_username(payload["username"])
    # we must check salt because user password can change
    if user is None or user.salt != payload["salt"] or user.disabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not available anymore",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
