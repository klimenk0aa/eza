async def triggers_actions(triggers_id, actions_id, zapi):
    zapi_info = await zapi.apiinfo.version()
    zapi_version = zapi_info.split('.')
    api_version = int(zapi_version[0])*10+int(zapi_version[1])
    #api_version = 40
    triggers_actions = dict()
    actions = await zapi.action.get(selectFilter="extend" ,output=["filter"], actionids = actions_id, filter={"eventsource":"0"})
    triggers_info = await zapi.trigger.get(triggerids = triggers_id, 
                                    expandDescription=True, 
                                    selectGroups="groupid", 
                                    selectHosts="hostid", 
                                    selectTags="extend",
                                    selectItems="itemid", 
                                    output=["triggerid", "description", "priority", "templateid"])
    for trigger_info in triggers_info:
        trigger_data = dict()
        items = [ item["itemid"] for item in trigger_info["items"]]
        applications = await zapi.application.get(itemids=items, output = ["name"])

        app_name = [app["name"] for app in applications]
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
            tags = list({t["tag"] for t in trigger_info["tags"]})
            tags_values = trigger_info["tags"]
            trigger_data["25"] = tags
            trigger_data["26"] = tags_values

        def var_resolver(var):
            """ cond_type
                0 - группа узлов сети;
                1 - узел сети;
                2 - триггер;
                3 - имя триггера;
                4 - важность триггера;
                5 - значение триггера (PROBLEM/OK);
                6 - период времени; 
                13 - шаблон узла сети;
                15 - группа элементов данных;
                16 - проблема подавлена; 
                25 - тег события;
                26 - значения тега события."""
            """operators
                0 - (по умолчанию) =;
                1 - <>;
                2 - содержит;
                3 - не содержит;
                4 - в;
                5 - >=;
                6 - <=;
                7 - не в;
                8 - соответствует;
                9 - не соответствует;
                10 - Да;
                11 - Нет. """
            operators_simple = {
                "0": " in ",
                "1": " not in ",
                "4": " in ",
                "7": " not in "
            }
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
            return res



        actions_id = []
        #print(actions)
        for action in actions:
            if action["filter"]["eval_formula"]:
                for cond in action["filter"]["conditions"]:
                    res = var_resolver(cond)
                    exec("%s = %s" % (cond["formulaid"], res))
                action_complite = eval(action["filter"]["eval_formula"])
                if action_complite:
                    actions_id.append(action["actionid"])
        triggers_actions[trigger_info["triggerid"]] = actions_id
    return triggers_actions