import logging

import asab.web.rest
import asab.exceptions

from ..decorators import access_control

###

L = logging.getLogger(__name__)

###


class TenantHandler(object):
	"""
	Tenant management

	---
	tags: ["Tenant management"]
	"""

	def __init__(self, app, tenant_svc):
		self.App = app
		self.TenantService = tenant_svc
		self.NameProposerService = app.get_service("seacatauth.NameProposerService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/tenant", self.list)
		web_app.router.add_get("/tenants", self.search)
		web_app.router.add_get("/tenant/{tenant}", self.get)
		web_app.router.add_put("/tenant/{tenant}", self.update_tenant)
		web_app.router.add_put("/tenants", self.get_tenants_batch)

		web_app.router.add_post("/tenant", self.create)
		web_app.router.add_delete("/tenant/{tenant}", self.delete)

		web_app.router.add_get("/tenant_assign/{credentials_id}", self.get_tenants_by_credentials)
		web_app.router.add_put("/tenant_assign/{credentials_id}", self.set_tenants)
		web_app.router.add_post("/tenant_assign/{credentials_id}/{tenant}", self.assign_tenant)
		web_app.router.add_delete("/tenant_assign/{credentials_id}/{tenant}", self.unassign_tenant)

		web_app.router.add_put("/tenant_assign_many", self.bulk_assign_tenants)
		web_app.router.add_put("/tenant_unassign_many", self.bulk_unassign_tenants)

		web_app.router.add_get("/tenant_propose", self.propose_tenant_name)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get("/tenant", self.list)


	# IMPORTANT: This endpoint needs to be compatible with `/tenant` handler in Asab Tenant Service
	async def list(self, request):
		"""
		List all registered tenant IDs
		"""
		# TODO: This has to be cached agressivelly
		provider = self.TenantService.get_provider()
		result = []
		async for tenant in provider.iterate():
			result.append(tenant["_id"])
		return asab.web.rest.json_response(request, data=result)


	@access_control()
	async def search(self, request):
		"""
		Search tenants.
		Results include only the tenants that are authorized in the current session with
		`seacat:tenant:access` resource. To search all tenants, access to `authz:superuser` or `authz:tenant:access`
		is required.

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
		-	name: f
			in: query
			description: Filter string
			schema:
				type: string
		"""
		if not request.can_access_all_tenants:
			# List only tenants authorized in the current session
			# NOTE: This ignores pagination and filtering
			tenants = []
			for tenant, rs in request.Session.Authorization.Authz.items():
				if tenant == "*":
					continue
				if "seacat:tenant:access" in rs:
					tenants.append(await self.TenantService.get_tenant(tenant))
			count = len(tenants)
			return asab.web.rest.json_response(request, data={"data": tenants, "count": count})

		page = int(request.query.get("p", 1)) - 1
		limit = request.query.get("i")
		if limit is not None:
			limit = int(limit)

		filter = request.query.get("f", "")
		if len(filter) == 0:
			filter = None

		provider = self.TenantService.get_provider()

		count = await provider.count(filter=filter)

		tenants = []
		async for tenant in provider.iterate(page, limit, filter):
			tenants.append(tenant)

		result = {
			"data": tenants,
			"count": count,
		}

		return asab.web.rest.json_response(request, data=result)


	@access_control("seacat:tenant:access")
	async def get(self, request):
		"""
		Get tenant detail
		"""
		tenant_id = request.match_info.get("tenant")
		data = await self.TenantService.get_tenant(tenant_id)
		return asab.web.rest.json_response(request, data)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["id"],
		"additionalProperties": False,
		"properties": {
			"id": {
				"type": "string",
				"description": "Unique tenant ID. Can't be changed once the tenant has been created."}},
		"example": {
			"id": "acme-corp"}
	})
	@access_control("authz:superuser")  # TODO: "seacat:tenant:create"
	async def create(self, request, *, credentials_id, json_data):
		"""
		Create a tenant

		---
		security:
		- oAuth:
			- authz:superuser
		"""
		role_service = self.App.get_service("seacatauth.RoleService")
		tenant = json_data["id"]

		# Create tenant
		tenant_id = await self.TenantService.create_tenant(tenant, creator_id=credentials_id)

		# Assign tenant
		try:
			await self.TenantService.assign_tenant(credentials_id, tenant)
		except Exception as e:
			L.error("Error assigning tenant: {}".format(e), exc_info=True, struct_data={"cid": credentials_id, "tenant": tenant})

		# Create role
		role = "{}/admin".format(tenant)
		try:
			# Create admin role in tenant
			await role_service.create(role)
			# Assign tenant management resources
			await role_service.update(role, resources_to_set=[
				"seacat:tenant:access", "seacat:tenant:edit", "seacat:tenant:assign", "seacat:tenant:delete",
				"seacat:role:access", "seacat:role:edit", "seacat:role:assign"])
		except Exception as e:
			L.error("Error creating admin role: {}".format(e), exc_info=True, struct_data={"role": role})

		# Assign the admin role to the user
		try:
			await role_service.assign_role(credentials_id, role)
		except Exception as e:
			L.error("Error assigning role: {}".format(e), exc_info=True, struct_data={"cid": credentials_id, "role": role})

		return asab.web.rest.json_response(
			request, data={"result": "OK", "id": tenant_id})

	@asab.web.rest.json_schema_handler({
		"type": "object",
		"additionalProperties": False,
		"properties": {
			"description": {
				"type": "string",
				"description": "Human readable description."},
			"data": {
				"type": "object",
				"description":
					"Custom tenant data. Shallow JSON object that maps string keys "
					"to non-structured values.",
				"patternProperties": {
					"^[a-zA-Z][a-zA-Z0-9_-]{0,126}[a-zA-Z0-9]$": {"anyOf": [
						{"type": "string"},
						{"type": "number"},
						{"type": "boolean"},
						{"type": "null"}]}}}},
		"example": {
			"description": "ACME Corp Inc.",
			"data": {
				"email": "support@acmecorp.test",
				"very_corporate": True,
				"schema": "ECS"}}
	})
	@access_control("seacat:tenant:edit")
	async def update_tenant(self, request, *, json_data, tenant):
		"""
		Update tenant description and/or its structured data
		---
		security:
		- oAuth:
			- seacat:tenant:edit
		"""
		result = await self.TenantService.update_tenant(tenant, **json_data)
		return asab.web.rest.json_response(request, data=result)


	@access_control("seacat:tenant:delete")
	async def delete(self, request, *, tenant):
		"""
		Delete a tenant. Also delete all its roles and assignments linked to this tenant.

		---
		security:
		- oAuth:
			- authz:superuser
		"""
		await self.TenantService.delete_tenant(tenant)
		return asab.web.rest.json_response(request, {"result": "OK"})


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["tenants"],
		"properties": {
			"tenants": {
				"type": "array",
				"description": "List of the IDs of tenants to be set",
				"items": {"type": "string"}}},
		"example": {
			"tenants": ["acme-corp", "my-eshop"]}
	})
	@access_control("seacat:tenant:assign")
	async def set_tenants(self, request, *, json_data):
		"""
		Specify a set of accessible tenants for requested credentials ID

		The credentials entity will be granted access to the listed tenants
		and revoked access to the tenants that are not listed.
		The caller needs to have access to `authz:tenant:assign` resource for each tenant whose access
		is being granted or revoked.
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


	@access_control("seacat:tenant:assign")
	async def assign_tenant(self, request, *, tenant):
		"""
		Grant specified tenant access to requested credentials

		---
		security:
		- oAuth:
			- authz:tenant:assign
		"""
		await self.TenantService.assign_tenant(
			request.match_info["credentials_id"],
			tenant,
		)
		return asab.web.rest.json_response(request, data={"result": "OK"})


	@access_control("seacat:tenant:assign")
	async def unassign_tenant(self, request, *, tenant):
		"""
		Revoke specified tenant access to requested credentials

		The tenant's roles are unassigned in the process.

		---
		security:
		- oAuth:
			- authz:tenant:assign
		"""
		await self.TenantService.unassign_tenant(
			request.match_info["credentials_id"],
			tenant,
		)
		return asab.web.rest.json_response(request, data={"result": "OK"})


	@access_control("seacat:tenant:access")
	async def get_tenants_by_credentials(self, request):
		"""
		Get list of authorized tenants for requested credentials
		"""
		result = await self.TenantService.get_tenants(request.match_info["credentials_id"])
		return asab.web.rest.json_response(
			request, result
		)


	@asab.web.rest.json_schema_handler({
		"type": "array",
		"description": "List of credential IDs",
		"items": {"type": "string"},
		"example": ["mongodb:default:abc123def456", "htpasswd:local:zdenek"],
	})
	@access_control("seacat:tenant:access")
	async def get_tenants_batch(self, request, *, json_data):
		"""
		Get list of authorized tenants for each listed credential ID
		"""
		response = {
			cid: await self.TenantService.get_tenants(cid)
			for cid in json_data
		}
		return asab.web.rest.json_response(request, response)


	@access_control()
	async def propose_tenant_name(self, request):
		"""
		Propose name for a new tenant.
		"""
		proposed_tenant = self.NameProposerService.propose_name()
		# TODO: Check is the proposed tenant name is not already taken
		return asab.web.rest.json_response(request, {"tenant_id": proposed_tenant})


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["credential_ids", "tenants"],
		"properties": {
			"credential_ids": {
				"type": "array",
				"description": "List of the IDs of credentials to manage.",
				"items": {"type": "string"}},
			"tenants": {
				"type": "object",
				"description":
					"Tenants and roles to be assigned. \n\n"
					"The keys are the IDs of tenants to be granted access to. The values are arrays of the respective "
					"tenant's roles to be assigned. \n\n"
					"To grant tenant access without assigning any roles, "
					"leave the role array empty. \n\n"
					"To assign global roles, list them under the `'*'` key.",
				"patternProperties": {
					r"^\*$|^[a-z][a-z0-9._-]{2,31}$": {
						"type": "array",
						"description": "List of the tenant's roles to be assigned",
						"items": {"type": "string"}}}}},
		"example": {
			"credential_ids": [
				"mongodb:default:abc123def456", "htpasswd:local:zdenek"],
			"tenants": {
				"*": ["*/global-editor"],
				"acme-corp": ["acme-corp/user", "acme-corp/supervisor"],
				"my-eshop": []}},
	})
	@access_control("authz:superuser")
	# TODO: For single tenant bulks, require only "seacat:tenant:assign"
	async def bulk_assign_tenants(self, request, *, json_data):
		"""
		Grant tenant access and/or assign roles to a list of credentials

		---
		security:
		- oAuth:
			- authz:superuser
		"""
		credential_service = self.TenantService.App.get_service("seacatauth.CredentialsService")
		role_service = self.TenantService.App.get_service("seacatauth.RoleService")

		# Validate that all the credentials exist
		for credential_id in json_data["credential_ids"]:
			try:
				await credential_service.detail(credential_id)
			except KeyError:
				raise asab.exceptions.ValidationError("Credentials not found: {}".format(credential_id))

		# Validate that tenants and their roles exists
		for tenant, roles in json_data["tenants"].items():
			if tenant != "*":
				try:
					await self.TenantService.get_tenant(tenant)
				except KeyError:
					raise asab.exceptions.ValidationError("Tenant not found: {}".format(tenant))
			for role in roles:
				t, _ = role.split("/", 1)
				if t != tenant:
					# Role is not listed under its proper tenant
					raise asab.exceptions.ValidationError("Role {!r} not found in tenant {!r}".format(role, tenant))
				try:
					await role_service.get(role)
				except KeyError:
					raise asab.exceptions.ValidationError("Role not found: {}".format(role))

		error_details = []
		for tenant, roles in json_data["tenants"].items():
			for credential_id in json_data["credential_ids"]:
				if tenant != "*":
					success = False
					try:
						await self.TenantService.assign_tenant(
							credential_id, tenant, verify_tenant=False, verify_credentials=False)
						success = True
					except asab.exceptions.Conflict:
						L.info("Skipping: Tenant already assigned.", struct_data={
							"cid": credential_id, "tenant": tenant})
						success = True
					except Exception as e:
						L.error("Cannot assign tenant: {}".format(e), exc_info=True, struct_data={
							"cid": credential_id, "tenant": tenant})
						error_details.append({"cid": credential_id, "tenant": tenant})
					if not success:
						continue

				if len(roles) == 0:
					continue

				for role in roles:
					try:
						await role_service.assign_role(
							credential_id, role, verify_role=False, verify_credentials=False, verify_tenant=False)
					except asab.exceptions.Conflict:
						L.info("Skipping: Role already assigned.", struct_data={
							"cid": credential_id, "role": role})
					except Exception as e:
						L.error("Cannot assign role: {}".format(e), exc_info=True, struct_data={
							"cid": credential_id, "role": role})
						error_details.append({"cid": credential_id, "role": role})

		data = {
			"error_count": len(error_details),
			"error_details": error_details,
			"result": "OK"}
		return asab.web.rest.json_response(request, data=data)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["credential_ids", "tenants"],
		"properties": {
			"credential_ids": {
				"type": "array",
				"description": "List of the IDs of credentials to manage.",
				"items": {"type": "string"}},
			"tenants": {
				"type": "object",
				"description":
					"Tenants and roles to be unassigned. \n\n"
					"The keys are the IDs of tenants to be revoked access to. The values are arrays of the respective "
					"tenant's roles to be unassigned. \n\n"
					"To completely revoke credentials' access to the tenant, provide `\"UNASSIGN-TENANT\"` as the "
					"tenant value, instead of the array of roles. \n\n"
					"To unassign global roles, list them under the `\"*\"` key.",
				"patternProperties": {
					r"^\*$|^[a-z][a-z0-9._-]{2,31}$": {
						"anyOf": [
							{"type": "array", "items": {"type": "string"}},
							{"type": "string", "enum": ["UNASSIGN-TENANT"]}
						]}}}},
		"example": {
			"credential_ids": [
				"mongodb:default:abc123def456", "htpasswd:local:zdenek"],
			"tenants": {
				"*": ["*/global-editor"],
				"acme-corp": ["acme-corp/user", "acme-corp/supervisor"],
				"my-eshop": "UNASSIGN-TENANT"}},
	})
	@access_control("authz:superuser")
	# TODO: For single tenant bulks, require only "seacat:tenant:assign"
	async def bulk_unassign_tenants(self, request, *, json_data):
		"""
		Revoke tenant access and/or unassign roles from a list of credentials

		---
		security:
		- oAuth:
			- authz:superuser
		"""
		role_service = self.TenantService.App.get_service("seacatauth.RoleService")

		# Verify that roles are listed under their proper tenant
		for tenant, roles in json_data["tenants"].items():
			if roles == "UNASSIGN-TENANT":
				continue
			for role in roles:
				t, _ = role.split("/", 1)
				if t != tenant:
					raise asab.exceptions.ValidationError("Role {!r} not found in tenant {!r}".format(role, tenant))

		error_details = []
		for tenant, roles in json_data["tenants"].items():
			for credential_id in json_data["credential_ids"]:
				if roles == "UNASSIGN-TENANT":
					# If "UNASSIGN-TENANT" is provided instead of the role array
					# (e.g. `"my-tenant": "UNASSIGN-TENANT"`), revoke access to the tenant completely.
					# This also automatically unassigns all the tenant's roles
					if tenant == "*":
						raise asab.exceptions.ValidationError("Cannot unassign '*' because it is not a tenant.")
					try:
						await self.TenantService.unassign_tenant(credential_id, tenant)
					except KeyError:
						L.info("Skipping: Tenant not assigned.", struct_data={
							"cid": credential_id, "tenant": tenant})
					except Exception as e:
						L.error("Cannot unassign tenant: {}".format(e), exc_info=True, struct_data={
							"cid": credential_id, "tenant": tenant})
						error_details.append({"cid": credential_id, "tenant": tenant})
				else:
					# If any roles are listed under the tenant (e.g. `"my-tenant": ["my-tenant/user"]`),
					# unassign only those and keep the tenant access.
					for role in roles:
						try:
							await role_service.unassign_role(credential_id, role)
						except KeyError:
							L.info("Skipping: Role not assigned.", struct_data={
								"cid": credential_id, "role": role})
						except Exception as e:
							L.error("Cannot unassign role: {}".format(e), exc_info=True, struct_data={
								"cid": credential_id, "role": role})
							error_details.append({"cid": credential_id, "role": role})

		data = {
			"error_count": len(error_details),
			"error_details": error_details,
			"result": "OK"}
		return asab.web.rest.json_response(request, data=data)
