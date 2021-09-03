from fastapi import FastAPI, HTTPException, Depends
from typing import Optional, List
from pydantic import BaseModel
from functions import get_current_user
from routes import root, users_manage, instances_manage, zbx_host_info, zbx_user_info
from models import *
from tortoise.contrib.fastapi import  register_tortoise
from functions import *
import app_config

import uvicorn


app = FastAPI(title = "AZA")

app.include_router(users_manage.router)
app.include_router(root.router)
app.include_router(instances_manage.router)
app.include_router(zbx_host_info.router)
app.include_router(zbx_user_info.router)



class HTTP500(BaseModel):
	detail: str

class User(BaseModel):
	username: str
	permission: int

class UserInDB(User):
	password: str


register_tortoise(
	app,
	db_url=app_config.DB_URL,
	modules = {"models": ["models"]},
	generate_schemas = True,
	add_exception_handlers = True,
)


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, workers = app_config.UV_WORKERS )
