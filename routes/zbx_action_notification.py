from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel

from functions import *

class User(BaseModel):
	username: str
	permission: int

router = APIRouter(tags=["zbx_action"])

@router.get("/instance/{inst_id}/action/notifications/{action_id}")
async def get_action_notifications(
	inst_id: int,
	action_id: int,
	current_user: User = Depends(get_current_user)):
	zapi = await get_zapi_async(inst_id)
	result = await actions_notifications(zapi, action_id)
	await zapi.logout()
	if not result:
		raise HTTPException(status_code = 404, detail = f"No info for action {action_id}")
	return result[str(action_id)]

@router.get("/instance/{inst_id}/action/users/{action_id}")
async def get_action_users(
	inst_id: int,
	action_id: int,
	resolve_users: Optional[bool] = False,
	current_user: User = Depends(get_current_user)):
	zapi = await get_zapi_async(inst_id)
	result = await actions_users(zapi, action_id, resolve_users)
	await zapi.logout()
	if not result:
		raise HTTPException(status_code = 404, detail = f"No info for action {action_id}")
	return result[str(action_id)]