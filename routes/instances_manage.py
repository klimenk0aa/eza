from fastapi import APIRouter, HTTPException, Depends, status
from models import *
from pydantic import BaseModel
from typing import List, Optional
from tortoise.contrib.fastapi import HTTPNotFoundError
from functions import get_current_user

class User(BaseModel):
	username: str
	permission: int

class Status(BaseModel):
	message: str

class InstanceSafe(BaseModel):
	id: int
	inst_name: str
	inst_url: str 

response_model_answer = {
	404: {"model": HTTPNotFoundError},
	500: {"model": HTTPNotFoundError}
}


router = APIRouter(
    tags=["instances"]
)


@router.get("/instances", response_model = List[Instance_Pydantic_all])
async def get_instances(current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		return await Instance_Pydantic_all.from_queryset(Instances.all())
	else:
		raise HTTPException(status_code = 404, detail = f"Access denied")


@router.post("/instances", response_model = Instance_Pydantic)
async def create_instances(inst: Instance_Pydantic, current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		inst_obj = await Instances.create(**inst.dict(exclude_unset=True))
		return await Instance_Pydantic.from_tortoise_orm(inst_obj)
	else:
		raise HTTPException(status_code = 404, detail = f"Access denied")


@router.get("/instances/{inst_id}/", response_model = Instance_Pydantic_all, responses = response_model_answer)
async def get_instance(inst_id: int, current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		return await Instance_Pydantic_all.from_queryset_single(Instances.get(id = inst_id))
	else:
		raise HTTPException(status_code = 404, detail = f"Access denied")


@router.delete("/instances/{inst_id}/", response_model = Status, responses = response_model_answer)
async def delete_instance(inst_id: int, current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		deleted_count = await Instances.filter(id = inst_id).delete()
		if not deleted_count:
			raise HTTPException(status_code = 404, detail = f"Instance {inst_id} not found")
		return Status(message=f"Deleted instance {inst_id}")
	else:
		raise HTTPException(status_code = 404, detail = f"Access denied")


@router.put("/instances/{inst_id}/", response_model = Status, responses = response_model_answer)
async def update_instance(inst_id: int, inst: Instance_Pydantic, current_user: User = Depends(get_current_user)):
	if current_user.permission == 0:
		updated_count = await Instances.filter(id = inst_id).update(**inst.dict(exclude_unset=True))
		if not updated_count:
			raise HTTPException(status_code = 500, detail = f"Instance {inst_id} not updated")
		return Status(message = f"Updated instance {inst_id}")
	else:
		raise HTTPException(status_code = 404, detail = f"Access denied")

@router.get("/instances_info", response_model = List[InstanceSafe])
async def get_instances_info(current_user: User = Depends(get_current_user)):
	return await Instance_Pydantic_all.from_queryset(Instances.all())