import logging

import aiohttp.web
import asab.web.rest

from ..decorators import access_control

###

L = logging.getLogger(__name__)

###


class TenantHandler(object):

	def __init__(self, app, tenant_svc):
		self.App = app
		self.TenantService = tenant_svc
		self.NameProposerService = app.get_service("seacatauth.NameProposerService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_get('/tenant', self.list)
		web_app.router.add_get('/tenants', self.search)
		web_app.router.add_get('/tenant/{tenant}', self.get)
		web_app.router.add_put('/tenant/{tenant}/{key}', self.set_value)
		web_app.router.add_delete('/tenant/{tenant}/{key}', self.unset_value)

		web_app.router.add_post('/tenant', self.create)
		web_app.router.add_delete('/tenant/{tenant}', self.delete)

		web_app.router.add_get('/tenant_assign/{credentials_id}', self.get_tenants_by_credentials)
		web_app.router.add_put('/tenant_assign/{credentials_id}', self.set_tenants)
		web_app.router.add_post('/tenant_assign/{credentials_id}/{tenant}', self.assign_tenant)
		web_app.router.add_delete('/tenant_assign/{credentials_id}/{tenant}', self.unassign_tenant)

		web_app.router.add_get('/public/tenant_propose', self.propose_tenant)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get('/tenant', self.list)
		web_app_public.router.add_get('/public/tenant_propose', self.propose_tenant)


	# IMPORTANT: This endpoint needs to be compatible with `/tenant` handler in Asab Tenant Service
	async def list(self, request):
		# TODO: This has to be cached agressivelly
		provider = self.TenantService.get_provider()
		result = []
		async for tenant in provider.iterate():
			result.append(tenant['_id'])
		return asab.web.rest.json_response(request, data=result)


	async def search(self, request):
		page = int(request.query.get("p", 1)) - 1
		limit = request.query.get("i")
		if limit is not None:
			limit = int(limit)

		provider = self.TenantService.get_provider()

		count = await provider.count()

		tenants = []
		async for tenant in provider.iterate(page, limit):
			tenants.append(tenant)

		result = {
			"result": "OK",
			"data": tenants,
			"count": count,
		}

		return asab.web.rest.json_response(request, data=result)


	async def get(self, request):
		tenant_id = request.match_info.get("tenant")
		provider = self.TenantService.get_provider()
		tenant = await provider.get(tenant_id)
		return asab.web.rest.json_response(request, data=tenant)

	@access_control("authz:superuser")
	async def create(self, request, *, credentials_id):
		tenant = await request.json()
		provider = self.TenantService.get_provider()
		tenant_id = tenant['id']

		# Create tenant
		tenant_id = await provider.create(tenant_id, creator_id=credentials_id)

		if tenant_id is None:
			raise aiohttp.web.HTTPServerError()

		# TODO: configurable name
		role_id = "{}/admin".format(tenant_id)
		role_service = self.TenantService.App.get_service("seacatauth.RoleService")

		try:
			# Create admin role in tenant
			await role_service.create(role_id)
			# Assign "authz:tenant:admin" resource
			await role_service.update_resources(role_id, resources_to_set=["authz:tenant:admin"])
		except Exception as e:
			L.error("Error creating role", struct_data={
				"role": role_id,
				"error": type(e).__name__
			})

		if credentials_id is not None:
			# Assign the tenant to the user who created it
			try:
				tenants = await self.TenantService.get_tenants(credentials_id)
				tenants.append(tenant_id)
				await self.TenantService.set_tenants(credentials_id, tenants)
			except Exception as e:
				L.error("Error assigning tenant", struct_data={
					"cid": credentials_id,
					"tenant": tenant_id,
					"error": type(e).__name__
				})
			try:
				# Assign the role to the user
				roles = await role_service.get_roles_by_credentials(credentials_id, tenant_id)
				roles.append(role_id)
				await role_service.set_roles(credentials_id, {tenant_id}, roles)
			except Exception as e:
				L.error("Error assigning role", struct_data={
					"cid": credentials_id,
					"role": role_id,
					"error": type(e).__name__
				})

		return asab.web.rest.json_response(
			request,
			data={"result": "OK", "tenant": tenant_id},
			status=200
		)

	@asab.web.rest.json_schema_handler({
		"type": "object",
		"properties": {
			"value": {"type": "string"}
		}
	})
	@access_control("authz:tenant:admin")
	async def set_value(self, request, *, json_data, tenant):
		key = request.match_info["key"]
		value = json_data["value"]

		provider = self.TenantService.get_provider()
		result = await provider.set_value(tenant, key, value)

		return asab.web.rest.json_response(request, {"result": result})

	@access_control("authz:tenant:admin")
	async def unset_value(self, request, *, tenant):
		key = request.match_info["key"]

		provider = self.TenantService.get_provider()
		result = await provider.unset_value(tenant, key)

		return asab.web.rest.json_response(request, {"result": result})

	@access_control("authz:superuser")
	async def delete(self, request, *, tenant):
		"""
		Delete a tenant. Also delete all its roles and assignments linked to this tenant.
		"""
		provider = self.TenantService.get_provider()
		await provider.delete(tenant)
		return asab.web.rest.json_response(request, data={"result": "OK"})


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": [
			"tenants",
		],
		"properties": {
			"tenants": {
				"type": "array",
				"items": {
					"type": "string",
				},
			},
		}
	})
	@access_control()
	async def set_tenants(self, request, *, json_data):
		"""
		Helper method for bulk tenant un/assignment
		"""
		credentials_id = request.match_info["credentials_id"]
		data = await self.TenantService.set_tenants(
			session=request.Session,
			credentials_id=credentials_id,
			tenants=json_data["tenants"]
		)

		return asab.web.rest.json_response(
			request,
			data=data,
			status=200 if data["result"] == "OK" else 400
		)


	@access_control("authz:tenant:admin")
	async def assign_tenant(self, request, *, tenant):
		data = await self.TenantService.assign_tenant(
			request.match_info["credentials_id"],
			tenant,
		)

		return asab.web.rest.json_response(
			request,
			data=data,
			status=200 if data["result"] == "OK" else 400
		)


	@access_control("authz:tenant:admin")
	async def unassign_tenant(self, request, *, tenant):
		data = await self.TenantService.unassign_tenant(
			request.match_info["credentials_id"],
			tenant,
		)

		return asab.web.rest.json_response(
			request,
			data=data,
			status=200 if data["result"] == "OK" else 400
		)


	async def get_tenants_by_credentials(self, request):
		result = await self.TenantService.get_tenants(request.match_info["credentials_id"])
		return asab.web.rest.json_response(
			request, result
		)


	async def propose_tenant(self, request):
		proposed_tenant = self.NameProposerService.propose_name()
		# TODO: Check is the proposed tenant name is not already taken
		return asab.web.rest.json_response(request, {'tenant_id': proposed_tenant})
