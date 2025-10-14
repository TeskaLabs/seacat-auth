import typing

from .abc import RoleView


class CustomTenantRoleView(RoleView):
	"""
	View over proper (non-propagated) tenant roles.
	"""

	def __init__(self, storage_service, collection_name, tenant_id):
		super().__init__(storage_service, collection_name)
		self.TenantId = tenant_id


	async def get(self, role_id: str) -> dict:
		assert self._role_tenant_matches(role_id)
		return self._normalize_role(await self.StorageService.get(self.CollectionName, role_id))


	def _base_query(self) -> dict:
		return {"tenant": self.TenantId}


	def _role_tenant_matches(self, role_id: str) -> bool:
		return role_id.split("/")[0] == self.TenantId


	def _is_tenant_match(self, tenants: typing.Iterable[str]) -> bool:
		return self.TenantId in tenants


	def _normalize_role(self, role: dict) -> dict:
		role = super()._normalize_role(role)
		role["type"] = "tenant"
		return role
