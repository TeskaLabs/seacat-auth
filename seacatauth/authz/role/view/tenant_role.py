import typing

from ..utils import BoolFieldOp
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


	def _apply_tenant_match(
		self,
		tenant_match: typing.Tuple[typing.Iterable[str], BoolFieldOp],
		add_fields: dict,
		filter: dict,
		sort: dict,
	):
		is_tenant_match = self.TenantId in tenant_match[0]
		add_fields["tenant_match"] = is_tenant_match
		match (is_tenant_match, tenant_match[1]):
			case (True, BoolFieldOp.FILTER_FALSE) | (False, BoolFieldOp.FILTER_TRUE):
				# No results possible
				raise StopIteration()
			case _:
				# All results possible, sorting has no effect
				pass


	def _role_tenant_matches(self, role_id: str) -> bool:
		return role_id.split("/")[0] == self.TenantId


	def _normalize_role(self, role: dict) -> dict:
		role = super()._normalize_role(role)
		role["type"] = "tenant"
		return role
