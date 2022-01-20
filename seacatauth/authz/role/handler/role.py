import logging

import aiohttp.web
import asab
import asab.web.rest
import asab.web.authz
import asab.web.tenant
import asab.storage.exceptions

from ....decorators import access_control

#

L = logging.getLogger(__name__)

#


class RoleHandler(object):
	def __init__(self, app, rbac_svc):
		self.RBACService = rbac_svc
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.App = app

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/role", self.list_all)
		web_app.router.add_get("/role/{tenant}", self.list)
		web_app.router.add_get("/role/{tenant}/{role_name}", self.get)
		web_app.router.add_post("/role/{tenant}/{role_name}", self.create)
		web_app.router.add_delete("/role/{tenant}/{role_name}", self.delete)
		web_app.router.add_put("/role/{tenant}/{role_name}", self.update_resources)

	@access_control("authz:superuser")
	async def list_all(self, request):
		page = int(request.query.get('p', 1)) - 1
		limit = request.query.get('i', None)
		if limit is not None:
			limit = int(limit)

		result = await self.RoleService.list(None, page, limit)
		return asab.web.rest.json_response(
			request, result
		)

	@access_control()
	async def list(self, request, *, tenant):
		page = int(request.query.get('p', 1)) - 1
		limit = request.query.get('i', None)
		if limit is not None:
			limit = int(limit)

		result = await self.RoleService.list(tenant, page, limit)
		return asab.web.rest.json_response(request, result)

	@access_control()
	async def get(self, request, *, tenant):
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
		role_name = request.match_info["role_name"]
		role_id = "{}/{}".format(tenant, role_name)
		try:
			result = await self.RoleService.create(role_id)
		except ValueError:
			L.log(asab.LOG_NOTICE, "Invalid role_id: {}".format(role_id))
			raise aiohttp.web.HTTPBadRequest()
		except KeyError:
			L.log(asab.LOG_NOTICE, "Couldn't find role '{}'".format(role_id))
			raise aiohttp.web.HTTPNotFound()
		except asab.storage.exceptions.DuplicateError:
			L.log(asab.LOG_NOTICE, "Couldn't create role '{}'; already exists".format(role_id))
			raise aiohttp.web.HTTPConflict()
		return asab.web.rest.json_response(
			request, result
		)

	@access_control("authz:tenant:admin")
	async def delete(self, request, *, tenant):
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
		"properties": {
			"add": {
				"type": "array",
				"items": {
					"type": "string",
				},
			},
			"del": {
				"type": "array",
				"items": {
					"type": "string",
				},
			},
			"set": {
				"type": "array",
				"items": {
					"type": "string",
				},
			},
		}
	})
	@access_control("authz:tenant:admin")
	async def update_resources(self, request, *, json_data, tenant, resources):
		"""
		Sets, adds or removes resources from a specified role.
		Global roles can be edited by superuser only.
		"""
		is_superuser = "authz:superuser" in resources
		role_name = request.match_info["role_name"]
		role_id = "{}/{}".format(tenant, role_name)
		resources_to_set = json_data.get("set", None)
		resources_to_add = json_data.get("add", None)
		resources_to_remove = json_data.get("del", None)
		resources_to_assign = set().union(
			resources_to_set or [],
			resources_to_add or [],
			resources_to_remove or []
		)

		# Only superuser can un/assign "authz:superuser"
		if "authz:superuser" in resources_to_assign and not is_superuser:
			L.warning("Forbidden access: Assigning 'authz:superuser' resource", struct_data={
				"role_id": role_id,
				"tenant": tenant,
				"cid": request.CredentialsId
			})
			raise aiohttp.web.HTTPForbidden()

		try:
			result = await self.RoleService.update_resources(
				role_id,
				resources_to_set,
				resources_to_add,
				resources_to_remove
			)
		except ValueError:
			raise aiohttp.web.HTTPBadRequest()
		except KeyError:
			raise aiohttp.web.HTTPNotFound()
		return asab.web.rest.json_response(
			request,
			data={"result": result}
		)
