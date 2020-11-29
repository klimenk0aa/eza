#from pyzabbix.api import ZabbixAPI
from models import *
import trigger_resolve
from aiozabbix_fork import ZabbixAPI as ZabbixAPIAsync


async def get_zapi_async(inst_id: int):
	inst_params = await Instances.get(id = inst_id).values( )
	zapi = ZabbixAPIAsync(inst_params[0]['inst_url'])
	await zapi.login(inst_params[0]['inst_user'], inst_params[0]['inst_pass'])
	return zapi


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
	#return result_users_list
	return result_users_list

async def is_user_zabbixadmin(zapi, user_id):
	user = await zapi.user.get(userids = user_id, output= ['userid', 'type'])
	if user[0]['type'] == "3":
		return True
	else:
		return False

async def user_hosts(zapi, user_id, triggers, actions, only_enabled):
	if await is_user_zabbixadmin(zapi, user_id):
		hosts = await zapi.host.get( output = ["hostid", "name", "host"])
		user_host_groups_ids = [h['hostid'] for h in hosts]
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
	if triggers:
		user_host_groups_tag_filtered_ids = set(user_host_groups_ids) - exclude_groups
		user_hosts_tag_filtered_group_grant = { host['hostid'] for host in await zapi.host.get(hostids = list(user_host_groups_tag_filtered_ids), output = ["hostid"])}
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
		if not actions:
			for host in hosts:
				host['triggers'] =[]
				for trigger in triggers_avaliable:
					if {'hostid' : host['hostid']} in trigger['hosts']:
						host['triggers'].append({
							'triggerid':trigger['triggerid'],
							'description':trigger['description'],
							})
		else:
			if only_enabled:
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


async def host_notification(zapi, host_id):
	host_usergroups = await host_usersgroups(zapi, host_id)
	usersgroups_ids = host_usergroups['usersgroups_granted']
	users_ids = await host_users(zapi, usersgroups_ids)
	actions_users = await zapi.action.get(userids = users_ids, output = ['actionid'])
	actions_users_ids = [au['actionid'] for au in actions_users]
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
	return resolve

async def actions_notifications(zapi, actions_ids):
	actions = await zapi.action.get(actionids = actions_ids)
	res = actions
	return res