
from pydantic import BaseModel
from typing import Optional

class UserBase(BaseModel):
    username: str
    email: str
    role: Optional[str] = "user"

class UserCreate(UserBase):
    password: str



class UserRead(UserBase):
    id: int

    class Config:
        from_attributes = True

class UserLogin(BaseModel):
    username: str
    password: str



# {
#   "username": "test",
#   "email": "test@test.com",
#   "role": "user", # optional, defaults to "user"
#   "password": "test" "yefevfcevfe"
# }