from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel
from typing import List, Optional
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta
from functions import get_current_user
from models import Users, User_Pydantic_all, User_Pydantic

import app_config

SECRET_KEY = app_config.SECRET_KEY
ALGORITHM = app_config.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = app_config.ACCESS_TOKEN_EXPIRE_MINUTES

class User(BaseModel):
	username: str
	permission: int

class UserSecur(User):
	id: int
	username: str

class TokenData(BaseModel):
	username: Optional[str] = None

class Token(BaseModel):
	access_token: str
	token_type: str
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
	return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
	return pwd_context.hash(password)

async def get_user(username: str):
	user = await User_Pydantic_all.from_queryset_single(Users.get(username = username))
	if user:
		return user


async def authenticate_user(username: str, password: str):
	user = await get_user(username)
	if not user:
		return False
	if not verify_password(password, user.password):
		return False
	return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
	to_encode = data.copy()
	if expires_delta:
		expire = datetime.utcnow() + expires_delta
	else:
		expire = datetime.utcnow() + timedelta(minutes=150)
	to_encode.update({"exp": expire})
	encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
	return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
	credentials_exception = HTTPException(
		status_code=status.HTTP_401_UNAUTHORIZED,
		detail="Could not validate credentials",
		headers={"WWW-Authenticate": "Bearer"},
	)
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
		username: str = payload.get("sub")
		if username is None:
			raise credentials_exception
		token_data = TokenData(username=username)
	except JWTError:
		raise credentials_exception
	user = await get_user(username=token_data.username)
	if user is None:
		raise credentials_exception
	return user


router = APIRouter(tags=["users"])

@router.post("/create_user")
async def create_user(username: str, password: str, permission: int, current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		user_obj = await Users.create(username = username, password = get_password_hash(password), permission = permission)
		if user_obj:
			return {"username":username, "create": "OK"}
	else:
		raise HTTPException(status_code = 404, detail = f"You can't create users")


@router.put("/update_user_password")
async def update_user_password(username: str, password: str, current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		user_obj = await Users.filter(username = username).update(password = get_password_hash(password))
		if user_obj:
			return {"username":username, "update_password": "OK"}
	else:
		raise HTTPException(status_code = 404, detail = f"You can't update users")


@router.put("/update_user_permission")
async def update_user_permission(username: str, permission: int, current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		user_obj = await Users.filter(username = username).update(permission = permission)
		if user_obj:
			return {"username":username, "update_permission": "OK"}
	else:
		raise HTTPException(status_code = 404, detail = f"You can't update users")



@router.delete("/delete_user")
async def delete_user(username: str,current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		user_obj = await Users.filter(username = username).delete()
		if user_obj:
			return {"username":username, "delete": "OK"}
		else:
			raise HTTPException(status_code=404, detail=f"User {username} not found")
	else:
		raise HTTPException(status_code = 404, detail = f"You can't delete users")



@router.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
	return current_user


@router.get("/users/all/", response_model=List[UserSecur])
async def read_users_me(current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		users = await User_Pydantic_all.from_queryset(Users.all())
		return users
	else:
		raise HTTPException(status_code = 404, detail = f"Access denied")


@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
	user = await authenticate_user(form_data.username, form_data.password)
	if not user:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Incorrect username or password",
			headers={"WWW-Authenticate": "Bearer"},
		)
	access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
	access_token = create_access_token(
		data={"sub": user.username}, expires_delta=access_token_expires
	)
	return {"access_token": access_token, "token_type": "bearer"}

