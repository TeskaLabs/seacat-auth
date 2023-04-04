import logging

import aiohttp.web
import asab
import asab.web.rest
import asab.storage.exceptions

from ....decorators import access_control

#

L = logging.getLogger(__name__)

#


class RoleHandler(object):
	"""
	Manage roles

	---
	tags: ["Manage roles"]
	"""
	def __init__(self, app, role_svc):
		self.App = app
		self.RoleService = role_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/role", self.list_all)
		web_app.router.add_get("/role/{tenant}", self.list)
		web_app.router.add_get("/role/{tenant}/{role_name}", self.get)
		web_app.router.add_post("/role/{tenant}/{role_name}", self.create)
		web_app.router.add_delete("/role/{tenant}/{role_name}", self.delete)
		web_app.router.add_put("/role/{tenant}/{role_name}", self.update)


	@access_control("authz:superuser")
	async def list_all(self, request):
		"""
		List roles from all tenants

		---
		parameters:
		-	name: p
			in: query
			description: Page number
			schema:
				type: integer
		-	name: i
			in: query
			description: Items per page
			schema:
				type: integer
		-	name: resource
			in: query
			description: Show only roles that contain the specified resource
			schema:
				type: string
		"""
		return await self._list(request, tenant=None)

	@access_control()
	async def list(self, request, *, tenant):
		"""
		List tenant roles

		---
		parameters:
		-	name: p
			in: query
			description: Page number
			schema:
				type: integer
		-	name: i
			in: query
			description: Items per page
			schema:
				type: integer
		-	name: resource
			in: query
			description: Show only roles that contain the specified resource
			schema:
				type: string
		"""
		return await self._list(request, tenant=tenant)

	async def _list(self, request, *, tenant):
		page = int(request.query.get("p", 1)) - 1
		limit = request.query.get("i")
		if limit is not None:
			limit = int(limit)
		resource = request.query.get("resource")

		result = await self.RoleService.list(tenant, page, limit, resource=resource)
		return asab.web.rest.json_response(request, result)


	@access_control()
	async def get(self, request, *, tenant):
		"""
		Get role detail
		"""
		role_name = request.match_info["role_name"]
		role_id = "{}/{}".format(tenant, role_name)
		try:
			result = await self.RoleService.get(role_id)
		except ValueError:
			L.log(asab.LOG_NOTICE, "Invalid role_id: {}".format(role_id))
			raise aiohttp.web.HTTPBadRequest()
		except KeyError:
			L.log(asab.LOG_NOTICE, "Couldn't find role '{}'".format(role_id))
			raise aiohttp.web.HTTPNotFound()
		return asab.web.rest.json_response(
			request, result
		)


	@access_control("authz:tenant:admin")
	async def create(self, request, *, tenant):
		"""
		Create a new role
		"""
		role_name = request.match_info["role_name"]
		role_id = "{}/{}".format(tenant, role_name)
		result = await self.RoleService.create(role_id)
		return asab.web.rest.json_response(
			request, result,
			status=200 if result == "OK" else 400
		)


	@access_control("authz:tenant:admin")
	async def delete(self, request, *, tenant):
		"""
		Delete role
		"""
		role_name = request.match_info["role_name"]
		role_id = "{}/{}".format(tenant, role_name)

		try:
			result = await self.RoleService.delete(role_id)
		except ValueError:
			L.error("Invalid role_id", struct_data={"role_id": role_id})
			raise aiohttp.web.HTTPBadRequest()
		except KeyError:
			L.error("Couldn't find role", struct_data={"role_id": role_id})
			raise aiohttp.web.HTTPNotFound()
		return asab.web.rest.json_response(
			request, result
		)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"additionalProperties": False,
		"properties": {
			"description": {
				"type": "string"},
			"add": {
				"type": "array",
				"items": {"type": "string"},
			},
			"del": {
				"type": "array",
				"items": {"type": "string"},
			},
			"set": {
				"type": "array",
				"items": {"type": "string"},
			},
		}
	})
	@access_control("authz:tenant:admin")
	async def update(self, request, *, json_data, tenant):
		"""
		Edit role description and resources
		"""
		role_name = request.match_info["role_name"]
		role_id = "{}/{}".format(tenant, role_name)
		resources_to_set = json_data.get("set")
		resources_to_add = json_data.get("add")
		resources_to_remove = json_data.get("del")
		resources_to_assign = set().union(
			resources_to_set or [],
			resources_to_add or [],
			resources_to_remove or []
		)

		# Only superuser can edit global roles
		if tenant in (None, "*") and not request.is_superuser:
			L.warning("Not authorized to edit global roles", struct_data={
				"role_id": role_id,
				"cid": request.CredentialsId
			})
			raise aiohttp.web.HTTPForbidden()

		# Only superuser can un/assign "authz:superuser"
		if "authz:superuser" in resources_to_assign and not request.is_superuser:
			L.warning("Not authorized to assign 'authz:superuser' resource", struct_data={
				"role_id": role_id,
				"tenant": tenant,
				"cid": request.CredentialsId
			})
			raise aiohttp.web.HTTPForbidden()

		try:
			result = await self.RoleService.update(
				role_id,
				description=json_data.get("description"),
				resources_to_set=resources_to_set,
				resources_to_add=resources_to_add,
				resources_to_remove=resources_to_remove,
			)
		except ValueError:
			raise aiohttp.web.HTTPBadRequest()
		return asab.web.rest.json_response(
			request,
			data={"result": result}
		)
