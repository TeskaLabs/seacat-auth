import logging
import asab
import asab.contextvars
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.exceptions
import asab.utils

from ....models.const import ResourceId
from . import schema


L = logging.getLogger(__name__)


class RolesHandler(object):
	"""
	Assign or unassign roles

	---
	tags: ["Roles"]
	"""

	def __init__(self, app, role_svc):
		self.App = app
		self.RoleService = role_svc
		self.RBACService = app.get_service("seacatauth.RBACService")

		web_app = app.WebContainer.WebApp

		web_app.router.add_get("/admin/credentials/{credentials_id}/roles/*", self.get_credentials_global_roles)
		web_app.router.add_put("/admin/credentials/{credentials_id}/roles/*", self.set_credentials_global_roles)
		web_app.router.add_put("/admin/credentials/{credentials_id}/roles/*/{role_name}", self.assign_credentials_global_role)
		web_app.router.add_delete("/admin/credentials/{credentials_id}/roles/*/{role_name}", self.unassign_credentials_global_role)
		web_app.router.add_put("/admin/roles/*", self.batch_get_credentials_global_roles)
		web_app.router.add_get("/admin/role/*/{role_name}/credentials", self.get_global_role_credentials)

		web_app.router.add_get("/admin/credentials/{credentials_id}/roles/{tenant}", self.get_credentials_roles)
		web_app.router.add_put("/admin/credentials/{credentials_id}/roles/{tenant}", self.set_credentials_roles)
		web_app.router.add_put("/admin/credentials/{credentials_id}/roles/{tenant}/{role_name}", self.assign_credentials_role)
		web_app.router.add_delete("/admin/credentials/{credentials_id}/roles/{tenant}/{role_name}", self.unassign_credentials_role)
		web_app.router.add_put("/admin/roles/{tenant}", self.batch_get_credentials_roles)
		web_app.router.add_get("/admin/role/{tenant}/{role_name}/credentials", self.get_role_credentials)

		# DEPRECATED, BACKWARD COMPATIBILITY
		# >>>
		web_app.router.add_get("/roles/*/{credentials_id}", self.get_credentials_global_roles)
		web_app.router.add_put("/roles/*/{credentials_id}", self.set_credentials_global_roles)
		web_app.router.add_put("/roles/*", self.batch_get_credentials_global_roles)
		web_app.router.add_post("/role_assign/{credentials_id}/*/{role_name}", self.assign_credentials_global_role)
		web_app.router.add_delete("/role_assign/{credentials_id}/*/{role_name}", self.unassign_credentials_global_role)

		web_app.router.add_get("/roles/{tenant}/{credentials_id}", self.get_credentials_roles)
		web_app.router.add_put("/roles/{tenant}/{credentials_id}", self.set_credentials_roles)
		web_app.router.add_put("/roles/{tenant}", self.batch_get_credentials_roles)
		web_app.router.add_post("/role_assign/{credentials_id}/{tenant}/{role_name}", self.assign_credentials_role)
		web_app.router.add_delete("/role_assign/{credentials_id}/{tenant}/{role_name}", self.unassign_credentials_role)
		# <<<


	async def get_credentials_roles(self, request):
		"""
		Get credentials' roles

		---
		parameters:
		- 	name: expand
			in: query
			description: Expand the result and return the roles as objects rather than just role IDs.
				When in expanded mode, the endpoint also supports pagination, filtering and sorting.
			schema:
				type: boolean
				default: false
		-	name: p
			in: query
			description: Page number
				(Only available in expanded mode)
			schema:
				type: integer
		-	name: i
			in: query
			description: Items per page
				(Only available in expanded mode)
			schema:
				type: integer
		-	name: f
			in: query
			description: Filter by ID (substring match)
				(Only available in expanded mode)
			schema:
				type: string
		-	name: aresource
			in: query
			description: Show only roles that contain the specified resource
				(Only available in expanded mode)
			schema:
				type: string
		-	name: aassignment.assigned
			in: query
			description: Filter by whether the role is assigned to the credentials specified by the assign_cid parameter.
				(Only available in expanded mode)
			schema:
				type: string
				enum: ["true", "false", "any"]
		-	name: aassignment.editable
			in: query
			description: Filter by the assignability of the role to the credentials specified by the assign_cid parameter.
				(Only available in expanded mode)
			schema:
				type: string
				enum: ["true", "false", "any"]
		-	name: sdescription
			in: query
			description: Sort by the role description.
				(Only available in expanded mode)
			schema:
				type: string
				enum: ["a" ,"d"]
		-	name: sassignment.assigned
			in: query
			description:
				Sort by whether the role is assigned to the credentials specified by the assign_cid parameter.
				(Only available in expanded mode)
			schema:
				type: string
				enum: ["a" ,"d"]
		-	name: sassignment.editable
			in: query
			description:
				Sort by the assignability of the role to the credentials specified by the assign_cid parameter.
				(Only available in expanded mode)
		"""
		tenant_id = asab.contextvars.Tenant.get()
		return await self._get_credentials_roles(request, tenant_id=tenant_id)


	@asab.web.tenant.allow_no_tenant
	async def get_credentials_global_roles(self, request):
		"""
		Get credentials' global roles

		---
		parameters:
		- 	name: expand
			in: query
			description:
				Expand the result and return the roles as objects rather than just role IDs.
				When in expanded mode, the endpoint also supports pagination, filtering and sorting.
			schema:
				type: boolean
				default: false
		-	name: p
			in: query
			description: Page number
				(Only available in expanded mode)
			schema:
				type: integer
		-	name: i
			in: query
			description: Items per page
				(Only available in expanded mode)
			schema:
				type: integer
		-	name: f
			in: query
			description: Filter by ID (substring match)
				(Only available in expanded mode)
			schema:
				type: string
		-	name: aresource
			in: query
			description: Show only roles that contain the specified resource
				(Only available in expanded mode)
			schema:
				type: string
		-	name: aassignment.assigned
			in: query
			description: Filter by whether the role is assigned to the credentials specified by the assign_cid parameter.
				(Only available in expanded mode)
			schema:
				type: string
				enum: ["true", "false", "any"]
			default: "true"
		-	name: aassignment.editable
			in: query
			description: Filter by the assignability of the role to the credentials specified by the assign_cid parameter.
				(Only available in expanded mode)
			schema:
				type: string
				enum: ["true", "false", "any"]
			default: "any"
		-	name: sdescription
			in: query
			description: Sort by the role description.
				(Only available in expanded mode)
			schema:
				type: string
				enum: ["a" ,"d"]
		-	name: sassignment.assigned
			in: query
			description:
				Sort by whether the role is assigned to the credentials specified by the assign_cid parameter.
				(Only available in expanded mode)
			schema:
				type: string
				enum: ["a" ,"d"]
		-	name: sassignment.editable
			in: query
			description:
				Sort by the assignability of the role to the credentials specified by the assign_cid parameter.
				(Only available in expanded mode)
			schema:
				type: string
				enum: ["a" ,"d"]
		"""
		return await self._get_credentials_roles(request, tenant_id=None)


	async def _get_credentials_roles(self, request, tenant_id):
		creds_id = request.match_info["credentials_id"]
		expand = asab.utils.string_to_boolean(request.query.get("expand", "false"))
		if not expand:
			forbidden_params = {
				"p", "i", "f", "adescription", "aresource", "aassignment.assigned", "aassignment.editable",
				"s_id", "sdescription", "sassignment.assigned", "sassignment.editable"
			}
			if forbidden_params & set(request.query):
				raise asab.exceptions.ValidationError(
					"Pagination, filtering and sorting parameters {} are only allowed when 'expand=true'.".format(
						", ".join("{!r}".format(p) for p in forbidden_params)
					)
				)
			tenants = [] if tenant_id is None else [tenant_id]
			result = await self.RoleService.get_roles_by_credentials(creds_id, tenants=tenants)
		else:
			page = int(request.query.get("p", 1)) - 1
			limit = int(request.query["i"]) if "i" in request.query else None
			sort = []
			for param in ("s_id", "sdescription", "sassignment.assigned", "sassignment.editable"):
				if param in request.query:
					match request.query[param]:
						case "a":
							sort.append((param[1:], 1))
						case "d":
							sort.append((param[1:], -1))
						case _:
							raise asab.exceptions.ValidationError(
								"Sorting parameter {!r} must be 'a' (ascending) or 'd' (descending).".format(param))

			name_filter = request.query.get("f")
			resource_filter = request.query.get("aresource", None)
			description_filter = request.query.get("adescription", None)

			assigned_filter = request.query.get("aassignment.assigned")
			if assigned_filter in (None, ""):
				assigned_filter = True  # Default to True to show only assigned roles
			elif assigned_filter in ("all", "any"):
				assigned_filter = None
			else:
				assigned_filter = asab.utils.string_to_boolean(assigned_filter)

			assignable_filter = (
				asab.utils.string_to_boolean(request.query.get("aassignment.editable"))
				if request.query.get("aassignment.editable") not in (None, "", "all", "any")
				else None
			)
			result = await self.RoleService.list_roles(
				tenant_id=tenant_id,
				page=page,
				limit=limit,
				sort=sort,
				name_filter=name_filter,
				description_filter=description_filter,
				resource_filter=resource_filter,
				assign_cid=creds_id,
				assigned_filter=assigned_filter,
				assignable_filter=assignable_filter,
			)

		return asab.web.rest.json_response(request, result)


	@asab.web.rest.json_schema_handler(schema.BATCH_GET_CREDENTIALS_ROLES)
	@asab.web.tenant.allow_no_tenant
	async def batch_get_credentials_roles(self, request, *, json_data):
		"""
		Get the assigned roles for several credentials
		"""
		tenant = asab.contextvars.Tenant.get()
		response = {
			cid: await self.RoleService.get_roles_by_credentials(cid, tenants=[tenant])
			for cid in json_data
		}
		return asab.web.rest.json_response(request, response)


	@asab.web.rest.json_schema_handler(schema.BATCH_GET_CREDENTIALS_ROLES)
	@asab.web.tenant.allow_no_tenant
	async def batch_get_credentials_global_roles(self, request, *, json_data):
		"""
		Get the assigned global roles for several credentials
		"""
		response = {
			cid: await self.RoleService.get_roles_by_credentials(cid, tenants=[])
			for cid in json_data
		}
		return asab.web.rest.json_response(request, response)


	@asab.web.rest.json_schema_handler(schema.SET_CREDENTIALS_ROLES)
	@asab.web.auth.require(ResourceId.ROLE_ASSIGN)
	async def set_credentials_roles(self, request, *, json_data):
		"""
		Set credentials' roles

		For given credentials ID, assign listed roles and unassign existing roles that are not in the list.
		The scope is always a specific tenant + global roles.
		Caller with superuser access can set both tenant-specific and global roles.
		Caller without superuser access can set only tenant-specific roles.
		"""
		authz = asab.contextvars.Authz.get()
		tenant_id = asab.contextvars.Tenant.get()
		credentials_id = request.match_info["credentials_id"]
		requested_roles = json_data["roles"]

		# Determine whether global roles will be un/assigned
		if authz.has_superuser_access():
			include_global = True
		else:
			include_global = False

		await self.RoleService.set_roles(credentials_id, requested_roles, tenant_id, include_global)

		return asab.web.rest.json_response(request, {"result": "OK"})


	@asab.web.rest.json_schema_handler(schema.SET_CREDENTIALS_ROLES)
	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
	async def set_credentials_global_roles(self, request, *, json_data):
		"""
		Set credentials' global roles
		"""
		credentials_id = request.match_info["credentials_id"]
		requested_roles = json_data["roles"]
		await self.RoleService.set_roles(credentials_id, requested_roles, tenant="*", include_global=True)
		return asab.web.rest.json_response(request, {"result": "OK"})


	@asab.web.auth.require(ResourceId.ROLE_ASSIGN)
	async def assign_credentials_role(self, request):
		"""
		Assign role to credentials
		"""
		tenant_id = asab.contextvars.Tenant.get()
		role_id = "{}/{}".format(tenant_id, request.match_info["role_name"])
		await self.RoleService.assign_role(
			credentials_id=request.match_info["credentials_id"],
			role_id=role_id
		)
		return asab.web.rest.json_response(request, data={"result": "OK"})


	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
	async def assign_credentials_global_role(self, request):
		"""
		Assign global role to credentials
		"""
		role_id = "*/{}".format(request.match_info["role_name"])
		await self.RoleService.assign_role(
			credentials_id=request.match_info["credentials_id"],
			role_id=role_id
		)
		return asab.web.rest.json_response(request, data={"result": "OK"})


	@asab.web.auth.require(ResourceId.ROLE_ASSIGN)
	async def unassign_credentials_role(self, request):
		"""
		Unassign role from credentials
		"""
		tenant_id = asab.contextvars.Tenant.get()
		role_id = "{}/{}".format(tenant_id, request.match_info["role_name"])
		await self.RoleService.unassign_role(
			credentials_id=request.match_info["credentials_id"],
			role_id=role_id
		)
		return asab.web.rest.json_response(request, data={"result": "OK"})


	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
	async def unassign_credentials_global_role(self, request):
		"""
		Unassign global role from credentials
		"""
		role_id = "*/{}".format(request.match_info["role_name"])
		await self.RoleService.unassign_role(
			credentials_id=request.match_info["credentials_id"],
			role_id=role_id
		)
		return asab.web.rest.json_response(request, data={"result": "OK"})


	@asab.web.auth.require(ResourceId.ROLE_ACCESS)
	async def get_role_credentials(self, request):
		"""
		Get the list of credentials assigned to a role

		---
		parameters:
		-	p:
			in: query
			description: Page number
			schema:
				type: integer
		-	i:
			in: query
			description: Items per page
			schema:
				type: integer
		-	name: ids_only
			in: query
			description: Summarize the assignments to any array of credential IDs only
			schema:
				type: boolean
		"""
		tenant_id = asab.contextvars.Tenant.get()
		role_id = "{}/{}".format(tenant_id, request.match_info["role_name"])
		return await self._get_role_credentials(request, role_id)


	@asab.web.auth.require(ResourceId.ROLE_ACCESS)
	@asab.web.tenant.allow_no_tenant
	async def get_global_role_credentials(self, request):
		"""
		Get the list of credentials assigned to a global role

		---
		parameters:
		-	p:
			in: query
			description: Page number
			schema:
				type: integer
		-	i:
			in: query
			description: Items per page
			schema:
				type: integer
		-	name: ids_only
			in: query
			description: Summarize the assignments to any array of credential IDs only
			schema:
				type: boolean
		"""
		role_id = "*/{}".format(request.match_info["role_name"])
		return await self._get_role_credentials(request, role_id)


	async def _get_role_credentials(self, request, role_id: str):
		"""
		Get the list of credentials assigned to a role
		"""
		return await self.RoleService.list_role_credentials(
			role_id,
			page=int(request.query.get("p", 1)) - 1,
			limit=int(request.query["i"]) if "i" in request.query else None,
			ids_only=asab.utils.string_to_boolean(request.query.get("ids_only")),
		)
