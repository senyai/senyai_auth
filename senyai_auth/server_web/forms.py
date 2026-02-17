from __future__ import annotations
from typing import Annotated
from pydantic import (
    BaseModel,
    StringConstraints,
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
    prompt: Annotated[
        str, StringConstraints(max_length=1024, strip_whitespace=True)
    ]
    default_username: Annotated[
        str,
        StringConstraints(
            min_length=0,
            max_length=32,
            strip_whitespace=True,
        ),
    ]
    default_email: str
    default_display_name: Annotated[
        str,
        StringConstraints(min_length=0, max_length=79, strip_whitespace=True),
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
#         SecretStr, StringConstraints(min_length=8, max_length=64, strip_whitespace=True)
#     ]
#     contacts: Annotated[str, StringConstraints(min_length=0, max_length=1500)]


class RegisterForm(BaseForm):
    username: str
    password: str
    email: str
    display_name: str
    contacts: Annotated[str, StringConstraints(min_length=0, max_length=1024)]


class LoginForm(BaseForm):
    username: str
    password: str


# class LoginFormHTML(LoginForm):
#     csrf_token: str

#     def to_api(self):
#         return LoginForm(username=self.username, password=self.password)


class RoleForm(BaseForm):
    project_id: int
    name: str
    description: Annotated[
        str, StringConstraints(min_length=0, max_length=1024)
    ]
    permissions_api: str
    permissions_git: str
    permissions_storage: str
    permissions_extra: str


class UserData(BaseForm):
    id: int
    username: str
    display_name: str


class RoleData(BaseForm):
    id: int
    name: str
    description: str
    users: list[int]


class RoleManageData(BaseForm):
    users: list[UserData]
    role: RoleData
