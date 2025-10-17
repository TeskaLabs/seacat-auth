import typing

from .abc import RoleView


class GlobalRoleView(RoleView):
	"""
	View over global roles. Includes global roles with propagation.
	"""

	def __init__(self, storage_service, collection_name):
		super().__init__(storage_service, collection_name)


	async def get(self, role_id: str) -> dict:
		assert self._role_tenant_matches(role_id)
		return self._normalize_role(await self.StorageService.get(self.CollectionName, role_id))


	def _base_query(self) -> dict:
		return {"tenant": {"$exists": False}}


	def _role_tenant_matches(self, role_id: str):
		return role_id.split("/")[0] == "*"


	def _is_tenant_match(self, tenants: typing.Iterable[str]) -> bool:
		return None in tenants


	def _normalize_role(self, role: dict):
		role = super()._normalize_role(role)
		role["type"] = "global"
		return role
