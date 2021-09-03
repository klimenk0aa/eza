from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel
from functions import *

class User(BaseModel):
	username: str
	permission: int

router = APIRouter(tags=["zbx_user"])

@router.get("/instance/{inst_id}/user/search/{search_string}")
async def search_user(inst_id: int, search_string: str, current_user: User = Depends(get_current_user)):
	#zapi = await get_zapi(inst_id)
	zapi = await get_zapi_async(inst_id)
	user_result = await user_search(zapi, search_string)
	await zapi.logout()
	if not user_result:
		raise HTTPException(status_code = 404, detail = f"User not found for request :{search_string}")
	return user_result


@router.get("/instance/{inst_id}/user/hosts/{user_id}")
async def get_user_hosts(
	inst_id: int,
	user_id: int,
	get_triggers: Optional[bool] = False,
	get_actions: Optional[bool] = False, 
	only_enabled_actions: Optional[bool] = False, 
	current_user: User = Depends(get_current_user)):
	zapi = await get_zapi_async(inst_id)
	result = await user_hosts(zapi, user_id, get_triggers, get_actions, only_enabled_actions)
	await zapi.logout()
	if not result:
		raise HTTPException(status_code = 404, detail = f"No info for user {user_id}")
	return result


@router.get("/instance/{inst_id}/user/actions/{user_id}")
async def get_user_ations(
	inst_id: int,
	user_id: int,
	only_enabled_actions: Optional[bool] = False, 
	current_user: User = Depends(get_current_user)):
	zapi = await get_zapi_async(inst_id)
	result = await user_actions(zapi, user_id, only_enabled_actions)
	await zapi.logout()
	if not result:
		raise HTTPException(status_code = 404, detail = f"No info for user {user_id}")
	return result


@router.get("/instance/{inst_id}/user/user_groups/{user_id}")
async def get_user_user_groups(
	inst_id: int,
	user_id: int,
	resolve_users: Optional[bool] = False, 
	current_user: User = Depends(get_current_user)):
	zapi = await get_zapi_async(inst_id)
	result = await user_user_groups(zapi, user_id, resolve_users)
	await zapi.logout()
	if not result:
		raise HTTPException(status_code = 404, detail = f"No info for user {user_id}")
	return result