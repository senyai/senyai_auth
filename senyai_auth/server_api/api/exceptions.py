from __future__ import annotations
from fastapi import HTTPException, status
from pydantic import BaseModel


class ErrorResponse(BaseModel):
    detail: str


not_authorized_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="User is not authorized to perform this action",
    headers={"WWW-Authenticate": "Bearer"},
)


def response_description(description: str):
    return {
        "model": ErrorResponse,
        "description": description,
        "content": {"application/json": {"example": {"detail": description}}},
    }


def conflict_description(description: str, field: str):
    return {
        "description": description,
        "content": {
            "application/json": {
                "schema": {"$ref": "#/components/schemas/ValidationError"},
                "example": {
                    "detail": (
                        {
                            "loc": ("body", field),
                            "msg": description,
                            "type": "Conflict",
                        },
                    )
                },
            }
        },
    }


def conflict_exception(description: str, field: str):
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=(
            {
                "loc": ("body", field),
                "msg": description,
                "type": "Conflict",
            },
        ),
    )


response_for_get_current_user = {
    "model": ErrorResponse,
    "description": "Unauthorized — token invalid or user unavailable",
    "content": {
        "application/json": {
            "examples": {
                "invalid_credentials": {
                    "summary": "Invalid token",
                    "value": {"detail": "Could not validate credentials"},
                },
                "user_unavailable": {
                    "summary": "User gone",
                    "value": {"detail": "User is not available anymore"},
                },
            }
        }
    },
}

response_with_perm_check = {
    "model": ErrorResponse,
    "description": "Unauthorized — token invalid, user unavailable, or user not permitted",
    "content": {
        "application/json": {
            "examples": {
                "invalid_credentials": {
                    "summary": "Invalid token",
                    "value": {"detail": "Could not validate credentials"},
                },
                "user_unavailable": {
                    "summary": "User gone",
                    "value": {"detail": "User is not available anymore"},
                },
                "not_permitted": {
                    "summary": "Not permitted",
                    "value": {
                        "detail": "User is not authorized to perform this action"
                    },
                },
            }
        }
    },
}
