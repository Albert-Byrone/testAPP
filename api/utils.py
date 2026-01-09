from passlib.context import CryptContext
from config.database_config import SessionLocal
from datetime import datetime, timedelta
from jose import jwt
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status
from jose import JWTError
from .models import User
from sqlalchemy.orm import Session

pwd_context = CryptContext(schemes=["sha256_crypt"])
auth2_schema= OAuth2PasswordBearer(tokenUrl="login")

ACCESS_TOKEN_EXPIRE_MINUTES = 60
SECRET_KEY = "LHGRUEGREBGIEJPFPEFGIERGJUB"
ALGORITHM='HS256'

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_hashed_password(password: str):
    return pwd_context.hash(password)



def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)



def create_access_token(data: dict, expire_time: timedelta = None):
    to_encode = data.copy()
    if expire_time:
        expire = datetime.utcnow() + expire_time
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(auth2_schema), db: Session = Depends(get_db)):

    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    print("Toekn", token)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print("Payload", payload)
        user_id: int =payload.get('sub')
        if user_id is None:
            raise credential_exception
    except JWTError:
        raise credential_exception
    user =db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credential_exception
    return user