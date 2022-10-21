import logging
import re
import uuid

import asab
import asab.storage.exceptions

#

L = logging.getLogger(__name__)

#


class TenantService(asab.Service):
	TenantNamePattern = r"[a-z][a-z0-9._-]{2,31}"

	def __init__(self, app, service_name="seacatauth.TenantService"):
		super().__init__(app, service_name)
		self.TenantsProvider = None
		self.TenantNameRegex = re.compile("^{}$".format(self.TenantNamePattern))


	def create_provider(self, provider_id, config_section_name):
		assert (self.TenantsProvider is None)  # We support only one tenant provider for now
		_, creds, provider_type, provider_name = config_section_name.rsplit(":", 3)
		if provider_type == 'mongodb':
			from .providers.mongodb import MongoDBTenantProvider
			provider = MongoDBTenantProvider(self.App, provider_id, config_section_name)

		else:
			raise RuntimeError("Unsupported tenant provider '{}'".format(provider_type))

		self.TenantsProvider = provider


	async def get_tenant(self, tenant_id: str):
		return await self.TenantsProvider.get(tenant_id)


	async def create_tenant(self, tenant_id: str, creator_id: str = None):
		if not self.TenantNameRegex.match(tenant_id):
			euid = uuid.uuid4()
			L.error("Cannot create tenant: Invalid ID", struct_data={"t": tenant_id, "uuid": euid})
			return {
				"result": "INVALID-VALUE",
				"uuid": euid,
				"message":
					"Tenant ID must consist only of characters 'a-z0-9._-', "
					"start with a letter, and be between 3 and 32 characters long.",
			}

		try:
			tenant_id = await self.TenantsProvider.create(tenant_id, creator_id)
		except asab.storage.exceptions.DuplicateError:
			euid = uuid.uuid4()
			L.error("Cannot create tenant: ID already exists", struct_data={"t": tenant_id, "uuid": euid})
			return {
				"result": "CONFLICT",
				"uuid": euid,
				"message": "A tenant with the name '{}' already exists.".format(tenant_id),
			}

		if tenant_id is None:
			euid = uuid.uuid4()
			return {
				"result": "FAILED",
				"uuid": euid,
			}

		# TODO: configurable name
		role_id = "{}/admin".format(tenant_id)
		role_service = self.App.get_service("seacatauth.RoleService")

		if creator_id is not None:
			# Assign the tenant to the user who created it
			try:
				await self.assign_tenant(creator_id, tenant_id)
			except Exception as e:
				L.error("Error assigning tenant", struct_data={
					"cid": creator_id,
					"tenant": tenant_id,
					"reason": "{}: {}".format(type(e).__name__, e)
				})

		try:
			# Create admin role in tenant
			await role_service.create(role_id)
			# Assign "authz:tenant:admin" resource
			await role_service.update_resources(role_id, resources_to_set=["authz:tenant:admin"])
			role_created = True
		except Exception as e:
			role_created = False
			L.error("Error creating role:", struct_data={
				"role": role_id,
				"error": "{}: {}".format(type(e).__name__, str(e))
			})

		if creator_id is not None and role_created is True:
			# Assign the tenant admin role to the user
			try:
				await role_service.assign_role(creator_id, role_id)
			except Exception as e:
				L.error("Error assigning role", struct_data={
					"cid": creator_id,
					"role": role_id,
					"reason": "{}: {}".format(type(e).__name__, e)
				})

		return {
			"result": "OK",
			"id": tenant_id,
		}


	async def set_tenant_data(self, tenant_id: str, data: dict):
		result = await self.TenantsProvider.set_data(tenant_id, data)
		return {"result": result}


	async def delete_tenant(self, tenant_id: str):
		try:
			result = await self.TenantsProvider.delete(tenant_id)
		except KeyError:
			euid = uuid.uuid4()
			L.error("Cannot delete tenant: ID not found", struct_data={"t": tenant_id, "uuid": euid})
			return {
				"result": "NOT-FOUND",
				"uuid": euid,
			}

		if result is True:
			return {"result": "OK"}
		else:
			return {"result": "FAILED"}


	def get_provider(self):
		'''
		This method can return None when a 'tenant' feature is not enabled.
		'''
		return self.TenantsProvider


	async def get_tenants(self, credentials_id: str):
		assert (self.is_enabled())  # TODO: Replace this by a L.warning("Tenants are not configured.") & raise RuntimeError()
		# TODO: This has to be cached agressivelly
		result = []
		async for obj in self.TenantsProvider.iterate_assigned(credentials_id):
			result.append(obj['t'])
		return result


	async def set_tenants(self, session, credentials_id: str, tenants: list):
		"""
		Assign `credentials_id` to all tenants listed in `tenants`, unassign it from all tenants that are not listed.
		"""
		assert (self.is_enabled())  # TODO: Replace this by a L.warning("Tenants are not configured.") & raise RuntimeError()
		cred_svc = self.App.get_service("seacatauth.CredentialsService")
		rbac_svc = self.App.get_service("seacatauth.RBACService")

		# Check if credentials exist
		try:
			await cred_svc.detail(credentials_id)
		except KeyError:
			message = "Credentials not found"
			L.error(message, struct_data={"cid": credentials_id})
			return {
				"result": "NOT-FOUND",
				"message": message,
			}

		existing_tenants = set(await self.get_tenants(credentials_id))
		new_tenants = set(tenants)
		tenants_to_assign = new_tenants.difference(existing_tenants)
		tenants_to_unassign = existing_tenants.difference(new_tenants)

		for tenant in tenants_to_assign.union(tenants_to_unassign):
			# Check if tenant exists
			try:
				await self.TenantsProvider.get(tenant)
			except KeyError:
				message = "Tenant not found"
				L.error(message, struct_data={"tenant": tenant})
				return {
					"result": "NOT-FOUND",
					"message": message,
				}
			# Check permission
			if not rbac_svc.has_resource_access(session.Authorization.Authz, tenant, ["authz:tenant:admin"]):
				message = "Not authorized for tenant un/assignment"
				L.error(message, struct_data={
					"agent_cid": session.Credentials.Id,
					"tenant": tenant
				})
				return {
					"result": "NOT-AUTHORIZED",
					"message": message,
					"error_data": {"tenant": tenant},
				}

		failed_count = 0
		for tenant in tenants_to_assign:
			data = await self.assign_tenant(credentials_id, tenant)
			if data["result"] != "OK":
				failed_count += 1
		for tenant in tenants_to_unassign:
			data = await self.unassign_tenant(credentials_id, tenant)
			if data["result"] != "OK":
				failed_count += 1

		L.log(asab.LOG_NOTICE, "Tenants successfully assigned to credentials", struct_data={
			"cid": credentials_id,
			"agent_cid": session.Credentials.Id,
			"assigned_count": len(tenants_to_assign),
			"unassigned_count": len(tenants_to_unassign),
			"failed_count": failed_count,
		})
		return {"result": "OK"}


	async def assign_tenant(self, credentials_id: str, tenant: str):
		assert (self.is_enabled())
		# TODO: Possibly validate tenant and credentials here
		return await self.TenantsProvider.assign_tenant(credentials_id, tenant)


	async def unassign_tenant(self, credentials_id: str, tenant: str):
		assert (self.is_enabled())

		# Unassign tenant roles
		role_svc = self.App.get_service("seacatauth.RoleService")
		await role_svc.set_roles(
			credentials_id,
			tenant_scope={tenant},
			roles=[]
		)

		return await self.TenantsProvider.unassign_tenant(credentials_id, tenant)


	def is_enabled(self):
		'''
		Tenants are optional, SeaCat Auth can operate without tenant.
		'''
		return self.TenantsProvider is not None
