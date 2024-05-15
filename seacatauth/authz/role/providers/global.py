import re
import typing

from ....events import EventTypes
from .abc import RoleProvider


class GlobalRoleProvider(RoleProvider):
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
			yield role

	async def create(
		self,
		role_id: str,
		description: typing.Optional[str] = None,
		resources: typing.Optional[list] = None,
		is_shared: typing.Optional[bool] = None,
		**kwargs
	):
		assert self.role_tenant_matches(role_id)
		upsertor = self.StorageService.upsertor(self.CollectionName, role_id)
		upsertor.set("resources", resources or [])
		if description:
			upsertor.set("description", description)
		if is_shared:
			upsertor.set("shared", True)
		role_id = await upsertor.execute(event_type=EventTypes.ROLE_CREATED)
		return role_id


	async def get(self, role_id: str) -> dict:
		assert self.role_tenant_matches(role_id)
		return await self.StorageService.get(self.CollectionName, role_id)


	async def update(
		self,
		role_id: str,
		description: typing.Optional[str] = None,
		resources: typing.Optional[list] = None,
		is_shared: typing.Optional[bool] = None,
		**kwargs
	):
		assert self.role_tenant_matches(role_id)
		role = await self.get(role_id)
		upsertor = self.StorageService.upsertor(self.CollectionName, role_id, version=role["_v"])
		if resources is not None:
			upsertor.set("resources", list(resources))
		if description is not None:
			upsertor.set("description", description)
		if is_shared is not None:
			upsertor.set("shared", bool(is_shared))
		await upsertor.execute(event_type=EventTypes.ROLE_UPDATED)


	async def delete(self, role_id: str) -> dict:
		return await self.StorageService.delete(self.CollectionName, role_id)


	def role_tenant_matches(self, role_id: str):
		return role_id.split("/")[0] == "*"
