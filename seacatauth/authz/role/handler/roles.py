import logging

import aiohttp.web
import asab
import asab.web.rest
import asab.web.authz
import asab.web.tenant

from ....decorators import access_control

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
		web_app.router.add_post("/role_assign/{credentials_id}/{tenant}/{role_name}", self.assign_role)
		web_app.router.add_delete("/role_assign/{credentials_id}/{tenant}/{role_name}", self.unassign_role)

	@access_control()
	async def get_roles_by_credentials(self, request, *, tenant):
		creds_id = request.match_info["credentials_id"]
		try:
			result = await self.RoleService.get_roles_by_credentials(creds_id, tenant)
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
		except KeyError:
			raise aiohttp.web.HTTPNotFound()

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

		data = await self.RoleService.assign_role(
			credentials_id=request.match_info["credentials_id"],
			role_id=role_id
		)

		return asab.web.rest.json_response(
			request,
			data=data,
			status=200 if data["result"] == "OK" else 400
		)


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
