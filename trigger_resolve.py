import asyncio 
from asyncstdlib import cache

host_macro_cache = dict()


async def triggers_actions(triggers_id, actions_id, zapi):
    @cache
    async def macro_resolve(hostid, macro):
        #TODO: сделать нормальный кеш, выпилить глобальную переменную
        global host_macro_cache
        if hostid not in host_macro_cache.keys():
            host_usermacros_raw = await zapi.usermacro.get(hostids = hostid, output = ["macro", "value"])
            host_usermacros_dict = {m["macro"]:m["value"] for m in host_usermacros_raw}
            host_macro_cache[hostid] = host_usermacros_dict
        if macro in host_macro_cache[hostid]:
            resolved_value = host_macro_cache[hostid][macro]
        elif macro.split(":")[0]+"}" in host_macro_cache[hostid]:
            resolved_value = host_macro_cache[hostid][macro.split(":")[0]+"}"]
        else:
            resolved_value = ""
        return resolved_value
    api_version = await zapi.api_version


    actions = await zapi.action.get(selectFilter="extend" ,output=["filter"], actionids = actions_id, filter={"eventsource":"0"})
    triggers_info = await zapi.trigger.get(triggerids = triggers_id, 
                                    expandDescription=True, 
                                    selectGroups="groupid", 
                                    selectHosts="hostid", 
                                    selectTags="extend",
                                    selectItems="itemid", 
                                    output=["triggerid", "description", "priority", "templateid"])
    #optimaze start
    triggers_itemsids = {t['triggerid']:
                     [i['itemid'] for i in t['items']]
                     for t in triggers_info}
    items_ids = set()
    for t,v in triggers_itemsids.items():
        for i in v:
            items_ids.add(i)
    items_ids = list(items_ids)
    apps = await zapi.application.get(itemids = items_ids, selectItems="itemid", output= ["itemid", "name"])
    items_appname = dict()
    for app in apps:
        for i in app['items']:
            if i['itemid'] in items_appname.keys():
                items_appname[i['itemid']].append(app['name'])
            else:
                items_appname[i['itemid']] = [app['name']]
    triggers_app_names = dict()
    for t_id, i_id in triggers_itemsids.items():
        for i in i_id:
            if i in items_appname.keys():
                if t_id in triggers_app_names.keys():
                    triggers_app_names[t_id]+=items_appname[i]
                else:
                    triggers_app_names[t_id] = items_appname[i]
    #optimaze end
    #macro in tag resolv
    async def calc_trigger(trigger_info):
        operators_simple = {
            "0": " in ",
            "1": " not in ",
            "4": " in ",
            "7": " not in "
        }
        trigger_data = dict()
        items = [ item["itemid"] for item in trigger_info["items"]]

        app_name = list(set(triggers_app_names[trigger_info["triggerid"]])) if trigger_info["triggerid"] in triggers_app_names.keys() else []
        groups = [gr["groupid"] for gr in trigger_info["groups"]]
        hosts = [h["hostid"] for h in trigger_info["hosts"]]

        trigger_data["0"] = groups
        trigger_data["1"] = hosts
        trigger_data["2"] = [trigger_info["triggerid"]]
        trigger_data["3"] = [trigger_info["description"]]
        trigger_data["4"] = [trigger_info["priority"]]
        trigger_data["13"] = [trigger_info["templateid"]]
        trigger_data["15"] = app_name
        if api_version > 30:
            for t in trigger_info["tags"]:
                if t['tag'].startswith("{$") and t['tag'].endswith("}"):
                    t['tag'] = await macro_resolve(hosts[0], t['tag'])
                if t['value'].startswith("{$") and t['value'].endswith("}"):
                    t['value'] = await macro_resolve(hosts[0], t['value'])

            tags = list({t["tag"] for t in trigger_info["tags"]})
            tags_values = trigger_info["tags"]
            trigger_data["25"] = tags
            trigger_data["26"] = tags_values
        actions_id = []


        for action in actions:
            if action["filter"]["eval_formula"]:
                for var in action["filter"]["conditions"]:
                    if var["conditiontype"] in ["5", "6", "16"]:
                        res = True
                    else:
                        if var["operator"] in operators_simple:
                            if var["conditiontype"] != "26":
                                res = eval('var["value"] %s trigger_data[var["conditiontype"]]' % operators_simple[var["operator"]])
                            elif var["conditiontype"] == "26":
                                res = eval('{"tag" : var["value2"], "value" : var["value"]} %s trigger_data[var["conditiontype"]]' % operators_simple[var["operator"]])

                        elif var["operator"] == "2":
                            res = False 
                            for app in trigger_data[var["conditiontype"]]:
                                if var["value"] in app:
                                    res = True

                        elif var["operator"] == "3":
                            res = False
                            if trigger_data[var["conditiontype"]]:
                                for app in trigger_data[var["conditiontype"]]:
                                    if var["value"] not in app:
                                        res = True
                            else:
                               res = True
                        elif var["operator"] == "5":
                            res = False 
                            for app in trigger_data[var["conditiontype"]]:
                                if int(var["value"]) >=  int(app):
                                    res = True
                        elif var["operator"] == "6":
                            res = False 
                            for app in trigger_data[var["conditiontype"]]:
                                if int(var["value"]) <=  int(app):
                                    res = True

                    exec("%s = %s" % (var["formulaid"], res))
                action_complite = eval(action["filter"]["eval_formula"])
                if action_complite:
                    actions_id.append(action["actionid"])
        return trigger_info["triggerid"], actions_id
        
    result = await asyncio.gather(*[calc_trigger(trigger_info) for trigger_info in triggers_info])
    #debug caching macro resolve
    #print(macro_resolve.cache_info())
    return {r[0]:r[1] for  r in result}
