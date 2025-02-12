import logging
import typing

import asab.web.tenant.providers.abc
import asab.exceptions

from .exceptions import TenantNotFoundError


L = logging.getLogger(__name__)


class AsabTenantProvider(asab.web.tenant.providers.abc.TenantProviderABC):
	"""
	Custom provider for ASAB TenantService that verifies tenants directly using Seacat Auth TenantService.
	"""

	def __init__(self, app, tenant_service):
		super().__init__(app, tenant_service, config=None)
		self.SeacatAuthTenantService = app.get_service("seacatauth.TenantService")


	async def get_tenants(self) -> typing.Set[str]:
		return set(await self.SeacatAuthTenantService.list_tenant_ids())


	async def is_tenant_known(self, tenant: str) -> bool:
		try:
			await self.SeacatAuthTenantService.get_tenant(tenant)
			return True
		except TenantNotFoundError:
			return False


	async def update(self):
		pass
