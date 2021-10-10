from pypika.queries import AliasedQuery
from models import *
import trigger_resolve
from pydantic import BaseModel
from aiozabbix import ZabbixAPI
import app_config
import aiohttp
from typing import List, Optional
from jose import JWTError, jwt
from fastapi import HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
import app_config
SECRET_KEY = app_config.SECRET_KEY
ALGORITHM = app_config.ALGORITHM

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenData(BaseModel):
	username: Optional[str] = None

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

async def get_user(username: str):
	user = await User_Pydantic_all.from_queryset_single(Users.get(username = username))
	if user:
		return user





class ZabbixAPIAsync(ZabbixAPI):
	def __init__(self,
		server='http://localhost/zabbix',
		*,
		timeout=None,
		client_session=None,
		headers=None):
		self.url = server + '/api_jsonrpc.php'
		if client_session is None:
			self.client_session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=app_config.VERIFY_SSL), timeout = app_config.AIOHTTP_TIMEOUT)
		else:
			self.client_session = client_session
		self.timeout = timeout
		self.auth = ''
		self.shared_state = {'next_jsonrpc_id': 0}
		self.do_login = None
		self.headers = self.DEFAULT_HEADERS.copy()
		if headers is not None:
			self.headers.update(headers)


	@property
	async def api_version(self):
		zapi_info = await self.apiinfo.version()
		zapi_version = zapi_info.split('.')
		api_version = int(zapi_version[0])*10+int(zapi_version[1])
		return api_version


	async def logout(self):
		await self.user.logout()
		await self.client_session.close()


async def get_zapi_async(inst_id: int):
	inst_params = await Instances.get(id = inst_id).values( )
	zapi = ZabbixAPIAsync(inst_params[0]['inst_url'])
	await zapi.login(inst_params[0]['inst_user'], inst_params[0]['inst_pass'])
	return zapi

async def get_zapi_version(zapi):
	zapi_version = await zapi.apiinfo.version()
	maj, min, path = zapi_version.split(".")
	zapi_version_str = int(f"{maj}{min}")
	return zapi_version_str


async def user_search(zapi, search_string: str):
	users = await zapi.user.get(selectMedias= ["mediatypeid", "sendto"], output = ["userid", "alias", "name", "surname", "medias"])
	result_users_list = []
	for user in users:
		if search_string in user['alias'] or search_string in user['name'] or search_string in user['surname']:
			result_users_list.append(user)
		if user['medias']:
			for media in user['medias']:
				if type(media['sendto']) == str:
					if search_string in media['sendto']:
						result_users_list.append(user)
				elif type(media['sendto']) == list:
					positive_count = 0
					for sendto in media['sendto']:
						if search_string in sendto:
							positive_count +=1
					if positive_count:
						result_users_list.append(user)
	if result_users_list:
		result_users_list = { 
		user['userid'] :  {
			"alias" :  user['alias'],
			"name" :   user['name'],
			"surname": user['surname'],
			"medias"  :user['medias']
		}
		for user in result_users_list}
	return result_users_list

async def is_user_zabbixadmin(zapi, user_id):
	user = await zapi.user.get(userids = user_id, output= ['userid', 'type'])
	if user[0]['type'] == "3":
		return True
	else:
		return False

async def user_hosts(zapi, user_id, get_triggers, get_actions, only_enabled_actions):
	if await is_user_zabbixadmin(zapi, user_id):
		hosts = await zapi.host.get( output = ["hostid", "name", "host"])
		user_host_groups_ids = [g['groupid'] for g in await zapi.hostgroup.get( output = ["groupid"])]
		exclude_groups = set()
		access_deny_host_groups = set()
		exclude_tags = dict()
	else:
		usergroup_data = await zapi.usergroup.get(userids = user_id, selectRights = "extend", selectTagFilters = "extend")

		#группы узлов доступные пользователю
		access_deny_host_groups = set()
		access_grant_host_groups = set()
		exclude_tags = dict()  # словарь тегов, которые нужно фильтровать
		exclude_groups = set() # список групп узлов отфильтрованных тегами 
		for ug in usergroup_data:
			for perm in ug['rights']:
				if perm['permission'] == '0':
					access_deny_host_groups.add(perm['id'])
				else:
					access_grant_host_groups.add(perm['id'])
			# обработка фильтра тегов, используется ниже, для триггеров
			for tg in ug['tag_filters']:
				if tg['groupid'] in exclude_tags:
					exclude_tags[tg['groupid']][tg['tag']] = tg['value']
				else:
					exclude_tags[tg['groupid']] = {tg['tag']:tg['value']}
		for host_group_id, tags in exclude_tags.items():
			if '' in tags:
				exclude_groups.add(host_group_id)
		for eg in exclude_groups:
			exclude_tags.pop(eg, None)
		user_host_groups_ids = list(access_grant_host_groups - access_deny_host_groups)
		user_host_groups = await zapi.hostgroup.get(groupids = user_host_groups_ids, output = ['groupid', 'name'])

		#узлы доступные пользователю
		hosts_grant = await zapi.host.get(groupids = list(access_grant_host_groups), output =["hostid", "name"]) 
		hosts_deny = await zapi.host.get(groupids = list(access_deny_host_groups), output =["hostid", "name"])
		hosts_grant_ids = [hg['hostid'] for hg in hosts_grant]
		hosts_deny_ids = [hd['hostid'] for hd in hosts_deny]
		hosts_ids = list(set(hosts_grant_ids) - set(hosts_deny_ids))
		hosts = await zapi.host.get(hostids = hosts_ids, output = ["hostid", "name", "host"])
	if get_triggers:
		user_host_groups_tag_filtered_ids = set(user_host_groups_ids) - exclude_groups
		aux = await zapi.host.get(groupids = list(user_host_groups_tag_filtered_ids), output = ["hostid"])
		user_hosts_tag_filtered_group_grant = { host['hostid'] for host in await zapi.host.get(groupids = list(user_host_groups_tag_filtered_ids), output = ["hostid"])}
		if access_deny_host_groups:
			user_hosts_tag_filtered_group_denie = { host['hostid'] for host in await zapi.host.get(groupids = list(access_deny_host_groups), output = ["hostid"])}
		else:
			user_hosts_tag_filtered_group_denie = set()
		user_hosts_tag_filtered = user_hosts_tag_filtered_group_grant - user_hosts_tag_filtered_group_denie
		triggers = await zapi.trigger.get(hostids = list(user_hosts_tag_filtered), selectTags = "extend", selectGroups = ["groupid"], output = ["triggerid", "groups", "tags"])
		triggers_dict = {trigger['triggerid']:
		{
			'groups':[group['groupid'] for group in trigger['groups']],
			'tags':{tag['tag']:tag['value'] for tag in trigger['tags']}
			} 
		for trigger in triggers}
		

		trigger_exclude = set()
		for trigger, trigger_data  in triggers_dict.items():
			for group, tags in exclude_tags.items():
				if group in trigger_data['groups']:
					for tag, value in tags.items():
						if tag in trigger_data['tags']:
							if value == '':
								trigger_exclude.add(trigger)
							else:
								if value == trigger_data['tags'].get(tag):
									trigger_exclude.add(trigger)

		triggers_avaliable_ids_list = list(set(triggers_dict.keys()) - trigger_exclude)
		triggers_avaliable = await zapi.trigger.get(triggerids = triggers_avaliable_ids_list, expandDescription = True, selectHosts = ['hostid'], output = ['triggerid', 'description'])
		if not get_actions:
			for host in hosts:
				host['triggers'] =[]
				for trigger in triggers_avaliable:
					if {'hostid' : host['hostid']} in trigger['hosts']:
						host['triggers'].append({
							'triggerid':trigger['triggerid'],
							'description':trigger['description'],
							})

		else:
			if only_enabled_actions:
				action_filter = {"eventsource":"0", "status": "0"}
			else:
				action_filter = {"eventsource":"0"}
			actions_data_user = await zapi.action.get(userids = user_id, output = ['actionid', 'name'], filter=action_filter)
			if "usergroup_data" not in locals():
				usergroup_data = await zapi.usergroup.get(userids = user_id, output = ['usrgrpid'])
			usrgrpids = [ug['usrgrpid'] for ug in usergroup_data]
			actions_data_usergroup = await zapi.action.get(usrgrpids = usrgrpids, output = ['actionid', 'name'], filter=action_filter)
			actions_data = actions_data_user + actions_data_usergroup
			actions_ids = [a['actionid'] for a  in actions_data]
			actions_dict = {a['actionid']:a for a in actions_data}
			resolve = await trigger_resolve.triggers_actions(triggers_avaliable_ids_list, actions_ids, zapi)
			for host in hosts:
				host['triggers'] =[]
				for trigger in triggers_avaliable:
					if {'hostid' : host['hostid']} in trigger['hosts']:
						trigger_actions =[]
						if resolve[trigger['triggerid']]:
							for a in resolve[trigger['triggerid']]:
								trigger_actions.append(actions_dict[a])
						host['triggers'].append({
							'triggerid':trigger['triggerid'],
							'description':trigger['description'],
							'actions':trigger_actions
							})
	return hosts

async def host_usersgroups(zapi, host_id):
	hostgroups = await zapi.hostgroup.get(hostids = host_id)
	hostgroups_ids = [hg['groupid'] for hg in hostgroups]
	usersgroups_granted = set()
	usersgroups = await zapi.usergroup.get(output = ['usrgrpid','rights'], selectRights = ['id','permission'])
	for ug in usersgroups:
		if ug['rights']:
			for right in ug['rights']:
				if right['id'] in hostgroups_ids and right['permission'] in ["1","2","3"]:
					usersgroups_granted.add(ug['usrgrpid'])
	return {"usersgroups_granted":list(usersgroups_granted), 'hostgroups_ids': hostgroups_ids}

async def host_users(zapi, usersgroups):
	users = await zapi.user.get(usrgrpids = usersgroups, output =['userid'])
	users_ids = [u['userid'] for u in users]
	superadmins = await zapi.user.get(filter={"type":"3"})
	superadmin_ids = [sa['userid'] for sa in superadmins]
	result_users_ids = list(set(users_ids).union(set(superadmin_ids)))
	return result_users_ids


async def host_notification(zapi, host_id, resolve_users):
	host_usergroups = await host_usersgroups(zapi, host_id)
	usersgroups_ids = host_usergroups['usersgroups_granted']
	users_ids = await host_users(zapi, usersgroups_ids)
	actionids_users = await zapi.action.get(userids = users_ids, output = ['actionid'])
	actions_users_ids = [au['actionid'] for au in actionids_users]
	actions_usersgroups = await zapi.action.get(usrgrpids = usersgroups_ids, output = ['actionid'])
	actions_usersgroups_ids = [aug['actionid'] for aug in actions_usersgroups]
	actions_ids = list(set(actions_users_ids).union(set(actions_usersgroups_ids)))
	usersgroups_tagsfilter = await zapi.usergroup.get(usrgrpids = usersgroups_ids, selectTagFilters = ['groupid', 'tag', 'value'], output = ['usrgrpid', 'tag_filters'])
	triggers = await zapi.trigger.get(hostids = host_id, output = ['triggerid', 'tags'], selectTags = 'extend')
	triggers_tags = []
	triggers_exclude = set()
	for t in triggers:
		if t['tags']:
			triggers_tags.append(t)
	for ug_tf in usersgroups_tagsfilter:
		if ug_tf['tag_filters']:
			for t in ug_tf['tag_filters']:
				if t['groupid'] in host_usergroups['hostgroups_ids']:
					for tt in triggers_tags:
						for tag in tt['tags']:
							if t['value']:
								if t['tag'] == tag['tag'] and t['value'] == tag['value']:
									triggers_exclude.add(tt['triggerid'])
							else:
								if t['tag'] == tag['tag']:
									triggers_exclude.add(tt['triggerid'])

	triggers_ids_all = [t['triggerid'] for t in triggers]
	resolve = await trigger_resolve.triggers_actions(triggers_ids_all, actions_ids, zapi)
	if triggers_exclude:
		for t in triggers_exclude:
			resolve[t] = "-1"
	if resolve_users:
		all_actions = list(set(sum([a for t,a in resolve.items()],[])))
		actions_notifications_data_raw = await actions_notifications(zapi, all_actions)
		actions_notifications_data = {a:o['problem_operations']['notifications'][0] for a,o in actions_notifications_data_raw.items()}
		actions_users_data = await actions_users(zapi, all_actions, True)
		resolve_extend = dict()
		for triggerid, actions in resolve.items():
			operation_data = list()
			for action in actions:
				for operationid, operations in actions_notifications_data[action].items():
					for operation in operations:
						for user_operation_id, user_operation in actions_users_data[action]['operations_users'].items():
							for medias in user_operation:
								for mediaid, media in medias['medias'].items():
									if user_operation_id == operationid and media['mediatypeid'] == operation['mediatype_id'] and media['active'] == "0" and operation['mediatype_status'] == "0":
										operation['alias'] = medias['alias']
										operation['name'] = medias['name']
										operation['surname'] = medias['surname']
										operation['userid'] = media['userid']
										operation['sendto'] = media['sendto']
										operation['severity'] = media['severity']
										operation['period'] = media['period']
										#del operation['mediatype_status']
										operation_data.append(operation)
			resolve_extend[triggerid] = operation_data
		resolve = resolve_extend
	return resolve


async def user_actions(zapi, user_id, only_enabled_actions):
	return_fields = ['actionid', 'name']
	if only_enabled_actions:
		action_filter = {"eventsource":"0", "status": "0"}
	else:
		action_filter = {"eventsource":"0"}
	actions_data_user = await zapi.action.get(userids = user_id, output = return_fields, filter=action_filter)
	usergroup_data = await zapi.usergroup.get(userids = user_id, output = ['usrgrpid'])
	usrgrpids = [ug['usrgrpid'] for ug in usergroup_data]
	actions_data_usergroup = await zapi.action.get(usrgrpids = usrgrpids, output = return_fields, filter=action_filter)
	actions_data = actions_data_user + actions_data_usergroup
	actions_ids = [a['actionid'] for a  in actions_data]
	actions_dict = {a['actionid']:a for a in actions_data}
	res = await zapi.action.get(actionids = actions_ids, output = return_fields)
	return res


async def user_user_groups(zapi, user_id, resolve_users):
	return_fields = ['usrgrpid', 'name']
	selectUsers = False
	if resolve_users:
		selectUsers = ["userid", "alias", "name", "surname"]
		return_fields.append("users")
		res = await zapi.usergroup.get(userids = user_id, output = return_fields, selectUsers = selectUsers)
	else:
		res = await zapi.usergroup.get(userids = user_id, output = return_fields)
	return res

###action reslver START
def parse_time(time_string):
	if "h" in time_string:
		tick = "час"
		count = int(time_string.replace("h", ""))
	elif "m" in time_string:
		tick = "мин"
		count = int(time_string.replace("m", ""))
	elif "s" in time_string:
		tick = "сек"
		count = int(time_string.replace("s", ""))
	elif "d" in time_string:
		tick = "дн"
		count = int(time_string.replace("d", ""))
	else:
		tick = "сек"
		count = int(time_string)
	return count, tick

async def resolve_command(zapi, operation):
	operation_desc = dict()
	script_type = {
		"0" : "Пользовательский скрипт",
		"1" : "IPMI",
		"2" : "SSH",
		"3" : "Telnet",
		"4" : "Глобальный скрипт"
				  }
	operation_desc['command_type'] = script_type[operation['opcommand']['type']]
	operation_desc['command'] = operation['opcommand']['command']
	if operation['opcommand_hst']:
		hostids = []
		for h in operation['opcommand_hst']:
			hostids.append(h['hostid'])
		if hostids:
			hosts = await zapi.host.get(hostids = hostids, output = ['hostid', 'name'])
			hosts_dict = {h['hostid'] : h['name'] for h in hosts}
			operation_desc['target_hosts'] = hosts_dict
	if operation['opcommand_grp']:
		groupids = []
		for g in operation['opcommand_grp']:
			groupids.append(g['groupid'])
		if groupids:
			hostgroups = await zapi.hostgroup.get(groupids = groupids, output = ['groupid', 'name'])
			hostgroups_dict = {hg['groupid']:hg['name'] for hg in hostgroups}
			operation_desc['target_hostgroups'] = hostgroups_dict
	return operation_desc

def resolve_notification(operation, mediatypes_info, mediatypes_templates):
	mt_id = operation['opmessage']['mediatypeid']
	notification_desc = list()
	if mt_id > "0" and mt_id in mediatypes_templates.keys():
		mt = dict()
		if operation['opmessage']['default_msg'] == "0":
			mt['subject'] = operation['opmessage']['subject']
			mt['message'] = operation['opmessage']['message']
		elif operation['opmessage']['default_msg'] == "1":
			mt['source'] = "default message"
			mt['subject'] = mediatypes_templates[mt_id]['subject']
			mt['message'] = mediatypes_templates[mt_id]['message']
		mt['mediatype_id'] = mt_id
		mt['mediatype_name'] = mediatypes_info[mt_id]['name']
		mt['mediatype_status'] = mediatypes_info[mt_id]['status']
		notification_desc.append(mt)
	else:
		for m, m_data in mediatypes_info.items():
			if m in mediatypes_templates.keys():
				mt = dict()
				if operation['opmessage']['default_msg'] == "0":
					mt['subject'] = operation['opmessage']['subject']
					mt['message'] = operation['opmessage']['message']
				elif operation['opmessage']['default_msg'] == "1":
					mt['source'] = "default message"
					mt['subject'] = mediatypes_templates[m]['subject']
					mt['message'] = mediatypes_templates[m]['message']
				mt['mediatype_id'] = m
				mt['mediatype_name'] = m_data['name']
				mt['mediatype_status'] = m_data['status']
				notification_desc.append(mt)
	return {operation['operationid']:notification_desc}

async def actions_notifications(zapi, actions_id):
	if type(actions_id) != list:
		actions_id = [actions_id]
	actions = await zapi.action.get(actionids =actions_id, filter = {"eventsource":0, "status": 0}, 
					selectOperations = 'extend', 
					selectRecoveryOperations = 'extend',
					selectAcknowledgeOperations = 'extend')
	zapi_version= await get_zapi_version(zapi)
	mt_name = "name" if zapi_version>=44 else "description"
	mediatypes = await zapi.mediatype.get(selectMessageTemplates="extend", output = ["mediatypeid", "status", "message_templates", "type", mt_name])
	mediatypes_templates = {
		'problem' : dict(),
		'recovery': dict(),
		'ack' : dict()
	}
	mediatypes_info = {
		m['mediatypeid'] : {
			"name": m['name'],
			"type": m['type'],
			"status": m['status'],
		}
		for m in mediatypes
	}
	for m in mediatypes:
		for t in m['message_templates']:
			notification_text = dict()
			notification_text['subject'] = t['subject']
			notification_text['message'] = t['message']
			if t['eventsource'] == "0":
				if t['recovery'] == "0":
					mediatypes_templates['problem'][m['mediatypeid']] = notification_text
				if t['recovery'] == "1":
					mediatypes_templates['recovery'][m['mediatypeid']] = notification_text
				if t['recovery'] == "2":
					mediatypes_templates['ack'][m['mediatypeid']] = notification_text
	result_dict = dict()
	for a in actions:
		problem_operations_ntf = []
		problem_operations_cmd = []
		recovery_operations_ntf = []
		recovery_operations_cmd = []
		ack_operations_ntf = []
		ack_operations_cmd = []
		default_esc_period = a['esc_period']
		for op in a['operations']:
			if op['operationtype'] == "0":
				pn = resolve_notification(op, mediatypes_info, mediatypes_templates['problem'])
				if pn:
					problem_operations_ntf.append(pn)
			if op['operationtype'] == "1":
				pc = await resolve_command(zapi, op)
				if pc:
					problem_operations_cmd.append(pc)

		#recovery_operations
		for ro in a['recoveryOperations']:
			if ro['operationtype'] == "0":
				rn = resolve_notification(ro, mediatypes_info, mediatypes_templates['recovery'])
				if rn:
					recovery_operations_ntf.append(rn)
			if ro['operationtype'] == "1":
				rc = await resolve_command(zapi, ro)
				if rc:
					recovery_operations_cmd.append(rc)
			if ro['operationtype'] == "11":
				rn = resolve_notification(op, mediatypes_info, mediatypes_templates['recovery'])
				if rn:
					recovery_operations_ntf.append(rn)				

		#ack_operations
		for ao in a['acknowledgeOperations']:
			if ao['operationtype'] == "0":
				an = resolve_notification(ao, mediatypes_info, mediatypes_templates['ack'])
				if an:
					ack_operations_ntf.append(an)
			if ao['operationtype'] == "1":
				ac = await resolve_command(zapi, ao)
				if ac:
					ack_operations_cmd.append(ac)
		result_dict[a['actionid']] =  {
			"problem_operations": {
				"notifications" : problem_operations_ntf,
				"commands" : problem_operations_cmd
			},
			"recovery_operations": {
				"notifications" : recovery_operations_ntf,
				"commands" : recovery_operations_cmd
			},
			"acknowledge_operations":{
				"notifications" : ack_operations_ntf,
				"commands" : ack_operations_cmd
			}
		}
	return result_dict

async def actions_users(zapi, actions_id, resolve_users):
	if type(actions_id) != list:
		actions_id = [actions_id]
	actions = await zapi.action.get(actionids =actions_id, filter = {"eventsource":0}, 
					selectOperations = ['opmessage_grp', 'opmessage_usr','operationid'],
					output = ['operations', 'actionid', 'name', 'status']
					)
	result_dict = dict()
	for a in actions:
		operations_users = dict()
		for o in a['operations']:
			userids =  [u['userid'] for u in o['opmessage_usr']]
			groupids = [g['usrgrpid'] for g in o['opmessage_grp']]
			if groupids:
				users_in_groups = await zapi.user.get(usrgrpids = groupids, output = ['userids'])
				if users_in_groups:
					userids_from_groups = [u['userid'] for u in users_in_groups]
					if userids_from_groups:
						userids+=userids_from_groups
			operations_users[o['operationid']] = userids
		result_dict[a['actionid']] = {
			'name': a['name'],
			'status': a['status'],
			'operations_users': operations_users
		}

	if resolve_users:
		all_userids = list(
			set(
				sum(
					[
						sum(
							av['operations_users'].values(),[]
							) 
							for ak,av in result_dict.items()
					],[]
				)
			)
		)
		users_info = await zapi.user.get(userids = all_userids, output = ['userid', 'alias', 'name', 'surname'], selectMedias = 'extend')
		users_resolve_dict = {
			u['userid'] : {
				'alias':u['alias'],
				'name':u['name'],
				'surname': u['surname'], 
				'medias': {
					m['mediaid']:m	for m in u['medias']
				}
			}
			for u in users_info
		}
		result_dict = {
			actionid: {
				'name':action['name'],
				'status': action['status'],
				'operations_users': {
					operationid: [users_resolve_dict[user] for user in userids] 
					for operationid, userids in action['operations_users'].items()
				}
			}
			for actionid,action in result_dict.items()
		}
	return result_dict

###action reslver END
		
