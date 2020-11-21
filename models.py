from tortoise import fields, models
from tortoise.contrib.pydantic import pydantic_model_creator

class Users(models.Model):
	"""
	User auth model
	"""
	id = fields.IntField(pk = True)
	username = fields.CharField(max_length = 50, unique=True)
	password = fields.CharField(max_length = 300)
	permission = fields.IntField(pk = False, default = 2) #0-admin, 1-all_view,2-simple_user(default)
User_Pydantic_all = pydantic_model_creator(Users)
User_Pydantic = pydantic_model_creator(Users, exclude =["id"])


class Instances(models.Model):
	"""
	The Instances model
	"""
	id = fields.IntField(pk = True)
	inst_name = fields.CharField(max_length = 50, unique=True)
	inst_user = fields.CharField(max_length = 32)
	inst_pass = fields.CharField(max_length = 32)
	inst_url = fields.CharField(max_length = 128)
Instance_Pydantic_all = pydantic_model_creator(Instances)
Instance_Pydantic = pydantic_model_creator(Instances, exclude = ["id"])


