from __future__ import annotations
from typing import Annotated
from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    constr,
    ValidationError,
    SecretStr,
)


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


# class RegisterForm(BaseModel):
#     username: str
#     display_name: str
#     email: EmailStr

# class RegisterFormGet(RegisterForm):
#     prompt: str

# class RegisterFormPost(RegisterFormGet):
#     password: Annotated[
#         SecretStr, constr(min_length=8, max_length=64, strip_whitespace=True)
#     ]
#     contacts: Annotated[str, constr(min_length=0, max_length=1500)]


class RegisterForm(BaseForm):
    username: str
    password: str
    email: str
    display_name: str


class RegisterFormAPI(RegisterForm):
    contacts: str


class RegisterFormHTML(RegisterForm):
    phone: str
    address: str
    csrf_token: str

    def to_api(self):
        return RegisterFormAPI(
            username=self.username,
            password=self.password,
            email=self.email,
            display_name=self.display_name,
            contacts="\n".join([self.phone, self.address]),
        )

class LoginForm(BaseForm):
    username: str
    password: str


class LoginFormHTML(LoginForm):
    csrf_token: str

    def to_api(self):
        return LoginForm(username=self.username, password=self.password)