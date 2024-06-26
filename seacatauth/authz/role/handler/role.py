import logging

import aiohttp.web
import asab
import asab.web.rest
import asab.storage.exceptions

from .... import exceptions
from ....decorators import access_control

#

L = logging.getLogger(__name__)

#


class RoleHandler(object):
	"""
	Manage roles

	---
	tags: ["Roles"]
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
		return await self._list(request, tenant_id=None)


	async def list(self, request):
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
			description: Show only roles that contain the specified resource.
			schema:
				type: string
		-	name: exclude_global
			in: query
			description: Show only proper tenant roles, without globals.
			schema:
				type: string
				enum:
				- true
		"""
		tenant_id = request.match_info["tenant"]
		if tenant_id == "*":
			asab.web.rest.json_response(request, {"result": "ACCESS-DENIED"}, status=403)
		return await self._list(request, tenant_id=tenant_id)

	async def _list(self, request, *, tenant_id):
		page = int(request.query.get("p", 1)) - 1
		limit = request.query.get("i")
		if limit is not None:
			limit = int(limit)
		filter_string = request.query.get("f")
		resource = request.query.get("resource")
		exclude_global = request.query.get("exclude_global", "false") == "true"

		result = await self.RoleService.list(
			tenant_id, page, limit, filter_string,
			resource=resource,
			exclude_global=exclude_global)
		return asab.web.rest.json_response(request, result)


	async def get(self, request):
		"""
		Get role detail
		"""
		tenant_id = request.match_info["tenant"]
		role_name = request.match_info["role_name"]
		role_id = "{}/{}".format(tenant_id, role_name)
		try:
			result = await self.RoleService.get(role_id)
		except KeyError:
			L.log(asab.LOG_NOTICE, "Couldn't find role '{}'".format(role_id))
			return aiohttp.web.HTTPNotFound()
		return asab.web.rest.json_response(request, result)


	@access_control("seacat:role:edit")
	async def create(self, request, *, tenant):
		"""
		Create a new role
		"""
		role_name = request.match_info["role_name"]
		role_id = "{}/{}".format(tenant, role_name)
		role_id = await self.RoleService.create(role_id)
		return asab.web.rest.json_response(request, {"result": "OK", "id": role_id})


	@access_control("seacat:role:edit")
	async def delete(self, request, *, tenant):
		"""
		Delete role
		"""
		role_name = request.match_info["role_name"]
		role_id = "{}/{}".format(tenant, role_name)

		try:
			result = await self.RoleService.delete(role_id)
		except KeyError:
			L.log(asab.LOG_NOTICE, "Role not found", struct_data={"role_id": role_id})
			return aiohttp.web.HTTPNotFound()
		return asab.web.rest.json_response(request, result)


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
	@access_control("seacat:role:edit")
	async def update(self, request, *, json_data, tenant):
		"""
		Edit role description and resources
		"""
		role_name = request.match_info["role_name"]
		role_id = "{}/{}".format(tenant, role_name)
		resources_to_set = json_data.get("set")
		resources_to_add = json_data.get("add")
		resources_to_remove = json_data.get("del")

		# Perform extra validations when the request is not superuser-authorized
		if not request.is_superuser:
			# Cannot edit global roles
			if tenant in (None, "*"):
				L.log(asab.LOG_NOTICE, "Not authorized to edit global roles", struct_data={
					"role_id": role_id,
					"cid": request.CredentialsId
				})
				return aiohttp.web.HTTPForbidden()

		try:
			result = await self.RoleService.update(
				role_id,
				description=json_data.get("description"),
				resources_to_set=resources_to_set,
				resources_to_add=resources_to_add,
				resources_to_remove=resources_to_remove,
			)
		except exceptions.RoleNotFoundError as e:
			L.log(asab.LOG_NOTICE, "Role not found", struct_data={"role_id": e.Role})
			return aiohttp.web.HTTPNotFound()
		return asab.web.rest.json_response(request, data={"result": result})
