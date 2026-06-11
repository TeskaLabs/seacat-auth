import logging
import typing

from .abc import TenantProviderABC


L = logging.getLogger(__name__)


class SystemTenantProvider(TenantProviderABC):

	Type = "system"


	def __init__(self, app, provider_id, config_section_name):
		super().__init__(app, provider_id, config_section_name)

		asab_tenant_service = app.get_service("asab.TenantService")
		self.AsabSystemTenantProvider = asab_tenant_service.get_provider("system")


	async def iterate(self, page: int = 1, limit: int = None, filter: str = None):
		for tenant_id in self.AsabSystemTenantProvider.get_tenants():
			if filter is None or filter.lower() in tenant_id:
				yield {"_id": tenant_id}


	async def count(self, filter=None) -> int:
		if filter is None:
			return len(self.AsabSystemTenantProvider.get_tenants())
		else:
			return len([
				tenant_id
				for tenant_id in self.AsabSystemTenantProvider.get_tenants()
				if filter.lower() in tenant_id
			])


	async def get(self, tenant_id) -> typing.Optional[dict]:
		if tenant_id in self.AsabSystemTenantProvider.get_tenants():
			return {"_id": tenant_id}
