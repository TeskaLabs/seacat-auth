import re
import typing

from .abc import RoleView


class GlobalRoleView(RoleView):
	def __init__(self, storage_service, collection_name):
		super().__init__(storage_service, collection_name)


	def _build_query(
		self,
		name_filter: typing.Optional[str] = None,
		resource_filter: typing.Optional[str] = None,
		**kwargs
	):
		query = {"tenant": None}
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
		return self._normalize_role(await self.StorageService.get(self.CollectionName, role_id))


	def _role_tenant_matches(self, role_id: str):
		return role_id.split("/")[0] == "*"


	def _normalize_role(self, role: dict):
		role = super()._normalize_role(role)
		role["type"] = "global"
		return role
