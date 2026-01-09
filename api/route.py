from fastapi import APIRouter, HTTPException, Depends
from .schemas import UserCreate,UserRead, UserLogin
from jose import jwt
from .utils import get_db, verify_password, create_access_token, get_current_user
from .crud import get_user_by_username, get_user_by_email, create_user
from sqlalchemy.orm import Session

router = APIRouter()

@router.post("/register", response_model=UserRead)
def register(user: UserCreate , db: Session = Depends(get_db)):
    if get_user_by_username(db, user.username) or get_user_by_email(db, user.email):
        raise HTTPException(status_code=400, detail="User already exists")
    return create_user(db, user)

@router.post("/login")
def login(user_data:UserLogin, db: Session = Depends(get_db)):
    user = get_user_by_username(db, user_data.username)
    print("The User", user)
    if not user or not verify_password(user_data.password,user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid pasword or username")
    access_token = create_access_token(data={"sub": user.id})
    return {"access_token": access_token, "user": {"id": user.id, "username": user.username, "email": user.email}, "token_type": "bearer"}


@router.get("/me")
def get_me(current_user = Depends(get_current_user)):
    return current_user
