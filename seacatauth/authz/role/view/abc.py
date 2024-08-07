import typing
import abc


class RoleView(abc.ABC):
	def __init__(self, storage_service, collection_name):
		self.StorageService = storage_service
		self.CollectionName = collection_name

	async def count(
		self,
		name_filter: typing.Optional[str] = None,
		resource_filter: typing.Optional[str] = None,
		**kwargs
	) -> int | None:
		raise NotImplementedError()

	async def iterate(
		self,
		offset: int = 0,
		limit: typing.Optional[int] = None,
		name_filter: typing.Optional[str] = None,
		resource_filter: typing.Optional[str] = None,
		**kwargs
	) -> typing.AsyncGenerator:
		raise NotImplementedError()

	async def _iterate(
		self,
		offset: int = 0,
		limit: typing.Optional[int] = None,
		query: typing.Optional[dict] = None,
		sort: typing.Tuple[str, int] = ("_id", 1),
	) -> typing.AsyncGenerator:
		cursor = self.StorageService.Database[self.CollectionName].find(query)
		cursor.sort(*sort)
		if offset:
			cursor.skip(offset)
		if limit:
			cursor.limit(limit)
		async for role in cursor:
			yield role

	async def get(self, role_id: str) -> dict:
		raise NotImplementedError()

	def _role_tenant_matches(self, role_id: str):
		raise NotImplementedError()

	def _normalize_role(self, role: dict):
		if role.get("managed_by"):
			role["read_only"] = True
		return role
