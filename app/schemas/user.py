from datetime import datetime

from pydantic import BaseModel, EmailStr, ConfigDict, Field, model_validator, field_validator

from app.utils.user import optimal_password

class UserEmail(BaseModel):
    email: EmailStr = Field(..., examples=["string@example.com"])

class UserBase(UserEmail):
    username: str = Field(..., min_length=3, description="닉네임은 최소 3자 이상이어야 합니다.")
    email: EmailStr = Field(..., examples=["string@example.com"])

class UserIn(UserBase):
    password: str = Field(...)

    # field_validator는 비동기 함수를 지원하지 않는다.
    @field_validator("password")
    def password_validator(cls, password: str):
        optimal_password(password)
        return password

class UserUpdate(BaseModel):
    username: str | None = Field(None, min_length=3, description="닉네임은 최소 3자 이상이어야 합니다.")
    email: EmailStr | None = None

    @field_validator('email', mode='before')
    def empty_email_to_none(cls, email):
        if email is None:
            print("email is None")
            return None
        if isinstance(email, str) and email.strip() == '':
            return None
        return email


class UserPasswordUpdate(BaseModel):
    password: str | None = Field(None)

    @field_validator("password")
    def password_validator(cls, password: str | None) -> str | None:
        if not password:
            return password
        optimal_password(password)
        return password

class UserOut(UserBase):
    id: int
    img_path: str | None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

class EmailRequest(BaseModel):
    email: str
    type:str

class VerifyRequest(BaseModel):
    type: str | None = None
    old_email: str | None = None
    email: EmailStr
    authcode: str
    password: str | None = None


