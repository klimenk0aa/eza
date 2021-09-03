from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel

from functions import *

class User(BaseModel):
	username: str
	permission: int

router = APIRouter(tags=["zbx_host"])

@router.get("/instance/{inst_id}/host/notifications/{host_id}")
async def get_host_notifications(
	inst_id: int,
	host_id: int,
	current_user: User = Depends(get_current_user)):
	zapi = await get_zapi_async(inst_id)
	result = await host_notification(zapi, host_id)
	await zapi.logout()
	if not result:
		raise HTTPException(status_code = 404, detail = f"No info for host {host_id}")
	return result