import logging

import aiohttp.web
import asab
import asab.web.rest
import asab.web.authz
import asab.web.tenant
import asab.exceptions

from ....decorators import access_control
from .... import exceptions

#

L = logging.getLogger(__name__)

#


class RolesHandler(object):
	def __init__(self, app, role_svc):
		self.App = app
		self.RoleService = role_svc
		self.RBACService = app.get_service("seacatauth.RBACService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_get('/roles/{tenant}/{credentials_id}', self.get_roles_by_credentials)
		web_app.router.add_put('/roles/{tenant}/{credentials_id}', self.set_roles)
		web_app.router.add_put("/roles/{tenant}", self.get_roles_batch)
		web_app.router.add_post("/roles", self.bulk_assign_roles)
		web_app.router.add_post("/role_assign/{credentials_id}/{tenant}/{role_name}", self.assign_role)
		web_app.router.add_delete("/role_assign/{credentials_id}/{tenant}/{role_name}", self.unassign_role)

	@access_control()
	async def get_roles_by_credentials(self, request, *, tenant):
		creds_id = request.match_info["credentials_id"]
		try:
			result = await self.RoleService.get_roles_by_credentials(creds_id, [tenant])
		except ValueError as e:
			L.log(asab.LOG_NOTICE, str(e))
			raise aiohttp.web.HTTPBadRequest()
		except KeyError as e:
			L.log(asab.LOG_NOTICE, str(e))
			raise aiohttp.web.HTTPNotFound()
		return asab.web.rest.json_response(
			request, result
		)


	@asab.web.rest.json_schema_handler({
		"type": "array",
		"items": {"type": "string"}
	})
	@access_control()
	async def get_roles_batch(self, request, *, tenant, json_data):
		response = {
			cid: await self.RoleService.get_roles_by_credentials(cid, [tenant])
			for cid in json_data
		}
		return asab.web.rest.json_response(request, response)


	@asab.web.rest.json_schema_handler({
		'type': 'object',
		'properties': {
			'roles': {
				'type': 'array',
				"items": {
					"type": "string",
				},
			},
		}
	})
	@access_control("authz:tenant:admin")
	async def set_roles(self, request, *, json_data, tenant, resources):
		# TODO: PATCH request to set/unset only known roles
		"""
		For given credentials: Assigns all listed roles, unassigns what's not in the list.
		Cases:
		1) The requester is superuser AND requested `tenant` is "*":
			Only global roles can be un/assigned.
		2) The requester is superuser AND requested `tenant` is "tenant-name":
			Roles from "tenant-name/..." + global roles can be un/assigned.
		3) The requester is not superuser AND requested `tenant` is "tenant-name":
			Only "tenant-name/..." roles can be un/assigned.
		ELSE) In other cases the role assignment fails.
		"""
		credentials_id = request.match_info["credentials_id"]
		roles = json_data["roles"]

		tenant_scope = set()

		if "authz:superuser" in resources:
			tenant_scope.add("*")
		else:
			if tenant == "*":
				L.warning("Forbidden access: global roles un/assignment", struct_data={
					"cid": request.CredentialsId
				})
				raise aiohttp.web.HTTPForbidden()

		tenant_scope.add(tenant)

		try:
			await self.RoleService.set_roles(
				credentials_id,
				tenant_scope,
				roles
			)
		except ValueError:
			raise aiohttp.web.HTTPBadRequest()

		resp_data = {"result": "OK"}
		return asab.web.rest.json_response(
			request,
			data=resp_data,
		)


	@access_control("authz:tenant:admin")
	async def assign_role(self, request, *, tenant):
		role_id = "{}/{}".format(tenant, request.match_info["role_name"])
		if tenant == "*":
			# Assigning global roles requires superuser
			if not self.RBACService.is_superuser(request.Session.Authorization.Authz):
				message = "Missing permissions to un/assign global role"
				L.warning(message, struct_data={
					"agent_cid": request.Session.Credentials.Id,
					"role": role_id,
				})
				return asab.web.rest.json_response(
					request,
					data={
						"result": "FORBIDDEN",
						"message": message
					},
					status=403
				)

		await self.RoleService.assign_role(
			credentials_id=request.match_info["credentials_id"],
			role_id=role_id
		)

		return asab.web.rest.json_response(request, data={"result": "OK"})


	@access_control("authz:tenant:admin")
	async def unassign_role(self, request, *, tenant):
		role_id = "{}/{}".format(tenant, request.match_info["role_name"])
		if tenant == "*":
			# Unassigning global roles requires superuser
			if not self.RBACService.is_superuser(request.Session.Authorization.Authz):
				message = "Missing permissions to un/assign global role"
				L.warning(message, struct_data={
					"agent_cid": request.Session.Credentials.Id,
					"role": role_id,
				})
				return asab.web.rest.json_response(
					request,
					data={
						"result": "FORBIDDEN",
						"message": message
					},
					status=403
				)

		data = await self.RoleService.unassign_role(
			credentials_id=request.match_info["credentials_id"],
			role_id=role_id
		)

		return asab.web.rest.json_response(
			request,
			data=data,
			status=200 if data["result"] == "OK" else 400
		)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"additionalProperties": False,
		"required": ["filter"],
		"minProperties": 2,
		"maxProperties": 2,
		"properties": {
			"filter": {
				"type": "object",
				"minProperties": 1,
				"maxProperties": 1,
				"additionalProperties": False,
				"properties": {
					"has_tenant": {"type": "string"},
					"has_role": {"type": "string"}}},
			"assign_roles": {
				"type": "array",
				"items": {"type": "string"}},
			"unassign_roles": {
				"type": "array",
				"items": {"type": "string"}}}})
	@access_control("authz:superuser")
	async def bulk_assign_roles(self, request, *, json_data):
		# Query credentials by filter
		# Only a single-condition filter is supported
		if "has_tenant" in json_data["filter"]:
			tenant = json_data["filter"]["has_tenant"]
			provider = self.RoleService.TenantService.get_provider()
			assignments = await provider.list_tenant_assignments(tenant)
		elif "has_role" in json_data["filter"]:
			role = json_data["filter"]["has_role"]
			assignments = await self.RoleService.list_role_assignments(role)
		else:
			raise asab.exceptions.ValidationError("Unsupported filter: {!r}".format(json_data["filter"]))

		if assignments["count"] == 0:
			data = {"credentials_matched": 0}
			return asab.web.rest.json_response(request, data=data)

		if "assign_roles" in json_data:
			roles = json_data["assign_roles"]
			# If any of the requested roles does not exist, throw error
			for role in roles:
				await self.RoleService.get(role)
		elif "unassign_roles" in json_data:
			roles = json_data["unassign_roles"]
		else:
			raise asab.exceptions.ValidationError("Unknown operation")

		credential_ids = [a["c"] for a in assignments["data"]]

		error_details = []
		successful_count = 0
		for role in roles:
			for credential_id in credential_ids:
				try:
					await self.RoleService.assign_role(
						credential_id, role,
						verify_credentials=False,
						verify_role=False,
						verify_tenant=False,
					)
					successful_count += 1
				except asab.exceptions.Conflict:
					error_details.append({"cid": credential_id, "role": role, "error": "Role already assigned."})
				except exceptions.TenantNotAuthorizedError:
					error_details.append(
						{"cid": credential_id, "role": role, "error": "Credentials not authorized under tenant."})
				except Exception as e:
					L.error("Cannot assign role: {}".format(e), exc_info=True, struct_data={
						"cid": credential_id, "role": role})
					error_details.append({"cid": credential_id, "role": role, "error": "Server error."})

		data = {
			"credentials_matched": assignments["count"],
			"successful_count": successful_count,
			"error_count": len(error_details),
			"error_details": error_details
		}

		return asab.web.rest.json_response(request, data=data)
