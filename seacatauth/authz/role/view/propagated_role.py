import re
import typing

from .abc import RoleView


class PropagatedRoleView(RoleView):
	"""
	View over tenant roles projected from global roles that have propagation enabled.
	"""

	def __init__(self, storage_service, collection_name, tenant_id):
		super().__init__(storage_service, collection_name)
		self.TenantId = tenant_id


	def _build_query(
		self,
		name_filter: typing.Optional[str] = None,
		resource_filter: typing.Optional[str] = None,
		**kwargs
	):
		query = {"tenant": None, "propagated": True}
		if name_filter:
			query["_id"] = {"$regex": re.escape(name_filter)}
		if resource_filter:
			query["resources"] = resource_filter
		return query


	async def count(
		self,
		name_filter: typing.Optional[str] = None,
		resource_filter: typing.Optional[str] = None,
		**kwargs
	) -> int | None:
		query = self._build_query(name_filter=name_filter, resource_filter=resource_filter)
		return await self.StorageService.Database[self.CollectionName].count_documents(query)


	async def iterate(
		self,
		offset: int = 0,
		limit: typing.Optional[int] = None,
		sort: typing.Tuple[str, int] = ("_id", 1),
		name_filter: typing.Optional[str] = None,
		resource_filter: typing.Optional[str] = None,
		**kwargs
	) -> typing.AsyncGenerator:
		query = self._build_query(name_filter=name_filter, resource_filter=resource_filter)
		async for role in self._iterate(offset, limit, query, sort):
			yield self._normalize_role(role)


	async def get(self, role_id: str) -> dict:
		assert self._role_tenant_matches(role_id)
		return self._normalize_role(
			await self.StorageService.get(self.CollectionName, self._tenant_role_id_to_global(role_id)))


	def _role_tenant_matches(self, role_id: str):
		tenant_id, role_name = role_id.split("/")
		assert role_name[0] == "~"
		return tenant_id == self.TenantId


	def _global_role_id_to_tenant(self, role_id: str):
		tenant_id, role_name = role_id.split("/")
		assert tenant_id == "*"
		return "{}/~{}".format(self.TenantId, role_name)


	def _tenant_role_id_to_global(self, role_id: str):
		_, role_name = role_id.split("/")
		assert role_name[0] == "~"
		return "*/{}".format(role_name[1:])


	def _normalize_role(self, role: dict):
		role = super()._normalize_role(role)
		role["type"] = "tenant"
		role["global_role_id"] = role["_id"]
		role["_id"] = self._global_role_id_to_tenant(role["_id"])
		role["editable"] = False
		role["tenant"] = self.TenantId
		return role
