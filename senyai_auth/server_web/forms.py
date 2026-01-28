from __future__ import annotations
from typing import Annotated
from pydantic import BaseModel, EmailStr, Field, constr, ValidationError


class BaseForm(BaseModel):
    @classmethod
    def parse_form(cls, form: dict):
        try:
            return cls(**form), None
        except ValidationError as e:
            return None, e.errors()


class InviteForm(BaseForm):
    project_id: int
    prompt: Annotated[str, constr(max_length=1024, strip_whitespace=True)]
    default_username: Annotated[
        str,
        constr(
            max_length=32,
            to_lower=True,
            strip_whitespace=True,
            pattern=r"^[a-z_-]+$",
        ),
    ]
    default_email: EmailStr
    default_display_name: Annotated[
        str, constr(max_length=79, strip_whitespace=True, pattern=r"^[\W ]*$")
    ]
    roles: list[str]
