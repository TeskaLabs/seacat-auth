import typing

from ..utils import BoolFieldOp
from .abc import RoleView


class PropagatedRoleView(RoleView):
	"""
	View over tenant roles projected from global roles that have propagation enabled.
	"""

	def __init__(self, storage_service, collection_name, tenant_id):
		super().__init__(storage_service, collection_name)
		self.TenantId = tenant_id


	async def get(self, role_id: str) -> dict:
		assert self._role_tenant_matches(role_id)
		return self._normalize_role(
			await self.StorageService.get(self.CollectionName, self._propagated_role_id_to_global(role_id)))


	def _base_query(self) -> dict:
		return {"tenant": {"$exists": False}, "propagated": True}


	def _add_public_id(
		self,
		add_fields: dict,
	):
		add_fields["public_id"] = {
			"$concat": [self.TenantId, "/~", {"$substr": ["$_id", 2, -1]}]
		}


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


	def _role_tenant_matches(self, role_id: str):
		tenant_id, role_name = role_id.split("/")
		assert role_name[0] == "~"
		return tenant_id == self.TenantId


	def _global_role_id_to_propagated(self, role_id: str):
		return global_role_id_to_propagated(role_id, self.TenantId)


	def _propagated_role_id_to_global(self, role_id: str):
		_, role_name = role_id.split("/")
		assert role_name[0] == "~"
		return "*/{}".format(role_name[1:])


	def _normalize_role(self, role: dict):
		role = super()._normalize_role(role)
		role["type"] = "tenant"
		role["global_role_id"] = role["_id"]
		role["_id"] = self._global_role_id_to_propagated(role["_id"])
		role["read_only"] = True
		role["tenant"] = self.TenantId
		return role


def global_role_id_to_propagated(role_id: str, tenant_id: str):
	tenant_part, role_name = role_id.split("/")
	assert tenant_part == "*"
	return "{}/~{}".format(tenant_id, role_name)
