import logging
import aiohttp.web
import asab
import asab.contextvars
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.storage.exceptions
import asab.exceptions

from .... import exceptions
from .... import generic
from ....const import ResourceId


L = logging.getLogger(__name__)


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


	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
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
		return await self._list(request, tenant_id=request.match_info["tenant"])

	async def _list(self, request, *, tenant_id):
		search = generic.SearchParams(request.query)
		result = await self.RoleService.list(
			tenant_id=tenant_id,
			page=search.Page,
			limit=search.ItemsPerPage,
			name_filter=search.SimpleFilter,
			resource_filter=search.get("resource"),
		)
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


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"additionalProperties": False,
		"properties": {
			"label": {"type": "string"},
			"description": {"type": "string"},
			"propagated": {"type": "boolean"},
			"resources": {
				"type": "array",
				"items": {"type": "string"},
			},
		}
	})
	@asab.web.auth.require(ResourceId.ROLE_EDIT)
	async def create(self, request, *, tenant, json_data):
		"""
		Create a new role

		---
		parameters:
		-	name: copy
			in: query
			description:
				Copy resources and description from a specified existing role.
				Resources non-applicable for the new role will be excluded.
			schema:
				type: string
		"""
		role_name = request.match_info["role_name"]
		role_id = "{}/{}".format(tenant, role_name)
		try:
			role_id = await self.RoleService.create(role_id, from_role=request.query.get("copy"), **json_data)
		except exceptions.ResourceNotFoundError as e:
			return asab.web.rest.json_response(request, status=404, data={
				"result": "ERROR",
				"tech_err": "Resource not found.",
				"err_dict": {"resource_id": e.ResourceId},
			})
		except asab.exceptions.Conflict:
			return asab.web.rest.json_response(request, status=409, data={
				"result": "ERROR",
				"tech_err": "Role already exists.",
				"err_dict": {"role_id": role_id},
			})
		return asab.web.rest.json_response(request, {
			"result": "OK",
			"id": role_id
		})


	@asab.web.auth.require(ResourceId.ROLE_EDIT)
	async def delete(self, request, *, tenant):
		"""
		Delete role
		"""
		role_name = request.match_info["role_name"]
		role_id = "{}/{}".format(tenant, role_name)

		try:
			result = await self.RoleService.delete(role_id)
		except exceptions.RoleNotFoundError:
			return asab.web.rest.json_response(request, status=404, data={
				"result": "ERROR", "tech_err": "Role not found."})
		except exceptions.NotEditableError as e:
			return e.json_response(request)
		return asab.web.rest.json_response(request, result)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"additionalProperties": False,
		"properties": {
			"label": {"type": "string"},
			"description": {"type": "string"},
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
	@asab.web.auth.require(ResourceId.ROLE_EDIT)
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
				label=json_data.get("label"),
				description=json_data.get("description"),
				resources_to_set=resources_to_set,
				resources_to_add=resources_to_add,
				resources_to_remove=resources_to_remove,
			)
		except exceptions.RoleNotFoundError:
			return asab.web.rest.json_response(request, status=404, data={
				"result": "ERROR", "tech_err": "Role not found."})
		except exceptions.NotEditableError as e:
			return e.json_response(request)
		return asab.web.rest.json_response(request, data={"result": result})
