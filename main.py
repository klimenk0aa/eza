from fastapi import FastAPI, HTTPException, Depends, status
from typing import Optional, List
from pydantic import BaseModel

from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

from models import *
from tortoise.contrib.fastapi import HTTPNotFoundError, register_tortoise

from functions import *
import app_config

SECRET_KEY = app_config.SECRET_KEY
ALGORITHM = app_config.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = app_config.ACCESS_TOKEN_EXPIRE_MINUTES


app = FastAPI(title = "AZA")

class Status(BaseModel):
	message: str

class HTTP500(BaseModel):
	detail: str

class Token(BaseModel):
	access_token: str
	token_type: str

class TokenData(BaseModel):
	username: Optional[str] = None

class User(BaseModel):
	username: str
	permission: int

class UserInDB(User):
	password: str

class UserSecur(User):
	id: int
	username: str

class InstanceSafe(BaseModel):
	id: int
	inst_name: str
	inst_url: str 


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


aza_help = """
AZA help message 
"""


response_model_answer = {
							404: {"model": HTTPNotFoundError},
							500: {"model": HTTPNotFoundError}
						}

#Start Auth section
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



@app.post("/token", response_model=Token)
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

@app.post("/create_user")
async def create_user(username: str, password: str, permission: int, current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		user_obj = await Users.create(username = username, password = get_password_hash(password), permission = permission)
		if user_obj:
			return {"username":username, "create": "OK"}
	else:
		raise HTTPException(status_code = 404, detail = f"You can't create users")


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
	return current_user


@app.get("/users/all/", response_model=List[UserSecur])
async def read_users_me(current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		users = await User_Pydantic_all.from_queryset(Users.all())
		return users
	else:
		raise HTTPException(status_code = 404, detail = f"Access denied")
#End Auth section


@app.get("/")
async def root():
	return {"info": aza_help}

#handle instabces objects
@app.get("/instances_info", response_model = List[InstanceSafe])
async def get_instances_info(current_user: User = Depends(get_current_user)):
	return await Instance_Pydantic_all.from_queryset(Instances.all())

@app.get("/instances", response_model = List[Instance_Pydantic_all])
async def get_instances(current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		return await Instance_Pydantic_all.from_queryset(Instances.all())
	else:
		raise HTTPException(status_code = 404, detail = f"Access denied")

@app.post("/instances", response_model = Instance_Pydantic)
async def create_instances(inst: Instance_Pydantic, current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		inst_obj = await Instances.create(**inst.dict(exclude_unset=True))
		return await Instance_Pydantic.from_tortoise_orm(inst_obj)
	else:
		raise HTTPException(status_code = 404, detail = f"Access denied")


@app.get("/instance/{inst_id}/", response_model = Instance_Pydantic_all, responses = response_model_answer)
async def get_instance(inst_id: int, current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		return await Instance_Pydantic_all.from_queryset_single(Instances.get(id = inst_id))
	else:
		raise HTTPException(status_code = 404, detail = f"Access denied")

@app.delete("/instance/{inst_id}/", response_model = Status, responses = response_model_answer)
async def delete_instance(inst_id: int, current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		deleted_count = await Instances.filter(id = inst_id).delete()
		if not deleted_count:
			raise HTTPException(status_code = 404, detail = f"Instance {inst_id} not found")
		return Status(message=f"Deleted instance {inst_id}")
	else:
		raise HTTPException(status_code = 404, detail = f"Access denied")

@app.put("/instance/{inst_id}/", response_model = Status, responses = response_model_answer)
async def update_instance(inst_id: int, inst: Instance_Pydantic, current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		updated_count = await Instances.filter(id = inst_id).update(**inst.dict(exclude_unset=True))
		if not updated_count:
			raise HTTPException(status_code = 500, detail = f"Instance {inst_id} not updated")
		return Status(message = f"Updated instance {inst_id}")
	else:
		raise HTTPException(status_code = 404, detail = f"Access denied")


@app.get("/instance/{inst_id}/user/search/{search_string}")
async def search_user(inst_id: int, search_string: str, current_user: User = Depends(get_current_user)):
	#zapi = await get_zapi(inst_id)
	zapi = await get_zapi_async(inst_id)
	user_result = await user_search(zapi, search_string)
	if not user_result:
		await zapi.logout()
		raise HTTPException(status_code = 404, detail = f"User not found for request :{search_string}")
	await zapi.logout()
	return user_result

@app.get("/instance/{inst_id}/user/hosts/{user_id}")
async def get_user_hosts(
	inst_id: int,
	user_id: int,
	triggers: Optional[bool] = False,
	actions: Optional[bool] = False, 
	only_enabled: Optional[bool] = False, 
	current_user: User = Depends(get_current_user)):
	zapi = await get_zapi_async(inst_id)
	result = await user_hosts(zapi, user_id, triggers, actions, only_enabled)
	if not result:
		await zapi.logout()
		raise HTTPException(status_code = 404, detail = f"No info for user {user_id}")
	await zapi.logout()
	return result

@app.get("/instance/{inst_id}/host/notifications/{host_id}")
async def get_host_notifications(
	inst_id: int,
	host_id: int,
	current_user: User = Depends(get_current_user)):
	zapi = await get_zapi_async(inst_id)
	result = await host_notification(zapi, host_id)
	if not result:
		await zapi.logout()
		raise HTTPException(status_code = 404, detail = f"No info for host {host_id}")
	await zapi.logout()
	return result

register_tortoise(
	app,
	db_url="sqlite://db.sqlite",
	modules = {"models": ["models"]},
	generate_schemas = True,
	add_exception_handlers = True,

)
