import logging
import asab
import asab.contextvars
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.storage.exceptions
import asab.exceptions
import asab.utils

from .... import exceptions
from ....models.const import ResourceId
from . import schema


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
		web_app.router.add_get("/role/*", self.list_global_roles)
		web_app.router.add_get("/role/*/{role_name}", self.get_global_role)
		web_app.router.add_post("/role/*/{role_name}", self.create_global_role)
		web_app.router.add_put("/role/*/{role_name}", self.update_global_role)
		web_app.router.add_delete("/role/*/{role_name}", self.delete_global_role)

		web_app.router.add_get("/role/{tenant}", self.list_roles)
		web_app.router.add_get("/role/{tenant}/{role_name}", self.get_role)
		web_app.router.add_post("/role/{tenant}/{role_name}", self.create_role)
		web_app.router.add_put("/role/{tenant}/{role_name}", self.update_role)
		web_app.router.add_delete("/role/{tenant}/{role_name}", self.delete_role)


	async def list_roles(self, request):
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
				type: boolean
		"""
		tenant_id = asab.contextvars.Tenant.get()
		return await self._list(request, tenant_id=tenant_id)


	@asab.web.tenant.allow_no_tenant
	async def list_global_roles(self, request):
		"""
		List global roles

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


	async def get_role(self, request):
		"""
		Get role detail
		"""
		tenant_id = asab.contextvars.Tenant.get()
		role_id = "{}/{}".format(tenant_id, request.match_info["role_name"])
		return await self._get_role(request, role_id)


	@asab.web.tenant.allow_no_tenant
	async def get_global_role(self, request):
		"""
		Get global role detail
		"""
		role_id = "*/{}".format(request.match_info["role_name"])
		return await self._get_role(request, role_id)


	@asab.web.rest.json_schema_handler(schema.CREATE_ROLE)
	@asab.web.auth.require(ResourceId.ROLE_EDIT)
	async def create_role(self, request, *, json_data):
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
		tenant_id = asab.contextvars.Tenant.get()
		role_id = "{}/{}".format(tenant_id, request.match_info["role_name"])
		return await self._create_role(request, role_id, json_data)


	@asab.web.rest.json_schema_handler(schema.CREATE_ROLE)
	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
	async def create_global_role(self, request, *, json_data):
		"""
		Create a new global role

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
		role_id = "*/{}".format(request.match_info["role_name"])
		return await self._create_role(request, role_id, json_data)


	@asab.web.rest.json_schema_handler(schema.UPDATE_ROLE)
	@asab.web.auth.require(ResourceId.ROLE_EDIT)
	async def update_role(self, request, *, json_data):
		"""
		Edit role description and resources
		"""
		tenant_id = asab.contextvars.Tenant.get()
		role_id = "{}/{}".format(tenant_id, request.match_info["role_name"])
		try:
			return await self._update_role(request, role_id, json_data)
		except asab.exceptions.ValidationError as e:
			return asab.web.rest.json_response(
				request,
				{"result": "ERROR", "tech_err": str(e)},
				status=400,
			)


	@asab.web.rest.json_schema_handler(schema.UPDATE_ROLE)
	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
	async def update_global_role(self, request, *, json_data):
		"""
		Edit global role description and resources
		"""
		role_id = "*/{}".format(request.match_info["role_name"])
		try:
			return await self._update_role(request, role_id, json_data)
		except asab.exceptions.ValidationError as e:
			return asab.web.rest.json_response(
				request,
				{"result": "ERROR", "tech_err": str(e)},
				status=400,
			)


	@asab.web.auth.require(ResourceId.ROLE_EDIT)
	async def delete_role(self, request):
		"""
		Delete role
		"""
		tenant_id = asab.contextvars.Tenant.get()
		role_id = "{}/{}".format(tenant_id, request.match_info["role_name"])
		return await self._delete_role(request, role_id)


	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
	async def delete_global_role(self, request):
		"""
		Delete global role
		"""
		role_id = "*/{}".format(request.match_info["role_name"])
		return await self._delete_role(request, role_id)


	async def _list(self, request, tenant_id):
		result = await self.RoleService.list(
			tenant_id=tenant_id,
			page=int(request.query.get("p", 1)) - 1,
			limit=int(request.query["i"]) if "i" in request.query else None,
			name_filter=request.query.get("f", None),
			resource_filter=request.query.get("aresource", None),
			exclude_global=asab.utils.string_to_boolean(request.query.get("exclude_global", "false"))
		)
		return asab.web.rest.json_response(request, result)


	async def _get_role(self, request, role_id):
		try:
			result = await self.RoleService.get(role_id)
		except KeyError:
			return asab.web.rest.json_response(
				request,
				{"result": "ERROR", "tech_err": "Role not found."},
				status=404
			)
		return asab.web.rest.json_response(request, result)


	async def _create_role(self, request, role_id, json_data):
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


	async def _update_role(self, request, role_id, json_data):
		try:
			result = await self.RoleService.update(
				role_id,
				label=json_data.get("label"),
				description=json_data.get("description"),
				resources_to_set=json_data.get("set"),
				resources_to_add=json_data.get("add"),
				resources_to_remove=json_data.get("del"),
			)
		except exceptions.RoleNotFoundError:
			return asab.web.rest.json_response(request, status=404, data={
				"result": "ERROR", "tech_err": "Role not found."})
		except exceptions.NotEditableError as e:
			return e.json_response(request)
		return asab.web.rest.json_response(request, data={"result": result})


	async def _delete_role(self, request, role_id):
		try:
			result = await self.RoleService.delete(role_id)
		except exceptions.RoleNotFoundError:
			return asab.web.rest.json_response(request, status=404, data={
				"result": "ERROR", "tech_err": "Role not found."})
		except exceptions.NotEditableError as e:
			return e.json_response(request)
		return asab.web.rest.json_response(request, result)
