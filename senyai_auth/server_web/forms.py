from __future__ import annotations
from typing import Annotated
from pydantic import (
    BaseModel,
    constr,
    ValidationError,
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
            min_length=0,
            max_length=32,
            strip_whitespace=True,
        ),
    ]
    default_email: str
    default_display_name: Annotated[
        str, constr(min_length=0, max_length=79, strip_whitespace=True)
    ]


class InviteFormAPI(InviteForm):
    roles: list[str]


class InviteFormHTML(InviteForm):
    is_manager: bool = False
    is_admin: bool = False
    # csrf_token: str

    def to_api(self):
        roles = ["user"]
        if self.is_manager:
            roles.append("manager")
        if self.is_admin:
            roles.append("admin")

        return InviteFormAPI(
            project_id=self.project_id,
            prompt=self.prompt,
            default_username=self.default_username,
            default_email=self.default_email,
            default_display_name=self.default_display_name,
            roles=roles,
        )


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
    phone: Annotated[str, constr(min_length=0, max_length=15)]
    address: Annotated[str, constr(min_length=0, max_length=1024)]

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


# class LoginFormHTML(LoginForm):
#     csrf_token: str

#     def to_api(self):
#         return LoginForm(username=self.username, password=self.password)
