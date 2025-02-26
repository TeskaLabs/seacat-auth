import logging
import asab
import asab.contextvars
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.exceptions

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


	async def get_credentials_roles(self, request):
		"""
		Get credentials' roles
		"""
		tenant_id = asab.contextvars.Tenant.get()
		creds_id = request.match_info["credentials_id"]
		result = await self.RoleService.get_roles_by_credentials(creds_id, tenants=[tenant_id])
		return asab.web.rest.json_response(request, result)


	@asab.web.tenant.allow_no_tenant
	async def get_credentials_global_roles(self, request):
		"""
		Get credentials' global roles
		"""
		creds_id = request.match_info["credentials_id"]
		result = await self.RoleService.get_roles_by_credentials(creds_id, tenants=[])
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

		For given credentials ID, assign listed roles and unassign existing roles that are not in the list

		Cases:
		1) The requester is superuser AND requested `tenant` is "tenant-name":
			Roles from "tenant-name/..." + global roles will be un/assigned.
		2) The requester is not superuser AND requested `tenant` is "tenant-name":
			Only "tenant-name/..." roles will be un/assigned.
		ELSE) In other cases the role assignment fails.
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
	async def unassign_credentials_role(self, request, *, tenant):
		"""
		Unassign role from credentials
		"""
		role_id = "{}/{}".format(tenant, request.match_info["role_name"])
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
