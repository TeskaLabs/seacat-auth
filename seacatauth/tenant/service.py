import logging

import asab
import asab.storage.exceptions

#

L = logging.getLogger(__name__)

#


class TenantService(asab.Service):


	def __init__(self, app, service_name="seacatauth.TenantService"):
		super().__init__(app, service_name)
		self.TenantsProvider = None


	def create_provider(self, provider_id, config_section_name):
		assert(self.TenantsProvider is None)  # We support only one tenant provider for now
		_, creds, provider_type, provider_name = config_section_name.rsplit(":", 3)
		if provider_type == 'mongodb':
			from .providers.mongodb import MongoDBTenantProvider
			provider = MongoDBTenantProvider(self.App, provider_id, config_section_name)

		else:
			raise RuntimeError("Unsupported tenant provider '{}'".format(provider_type))

		self.TenantsProvider = provider


	def get_provider(self):
		'''
		This method can return None when a 'tenant' feature is not enabled.
		'''
		return self.TenantsProvider


	async def get_tenants(self, credentials_id: str):
		assert(self.is_enabled())  # TODO: Replace this by a L.warning("Tenants are not configured.") & raise RuntimeError()
		# TODO: This has to be cached agressivelly
		result = []
		async for obj in self.TenantsProvider.iterate_assigned(credentials_id):
			result.append(obj['t'])
		return result


	# TODO: Refactor this using new assign_tenant and unassign_tenant methods
	async def set_tenants(self, credentials_id: str, tenant_ids: list):
		assert(self.is_enabled())  # TODO: Replace this by a L.warning("Tenants are not configured.") & raise RuntimeError()
		return await self.TenantsProvider.set_tenants(credentials_id, tenant_ids)


	async def assign_tenant(self, credentials_id: str, tenant: list):
		assert (self.is_enabled())
		# TODO: Possibly validate tenant and credentials here
		return await self.TenantsProvider.assign_tenant(credentials_id, tenant)


	async def unassign_tenant(self, credentials_id: str, tenant: list):
		assert (self.is_enabled())
		return await self.TenantsProvider.unassign_tenant(credentials_id, tenant)


	def is_enabled(self):
		'''
		Tenants are optional, SeaCat Auth can operate without tenant.
		'''
		return self.TenantsProvider is not None
