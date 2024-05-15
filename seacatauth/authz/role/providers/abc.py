import typing
import abc


class RoleProvider(abc.ABC):
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

	async def create(
		self,
		role_id: str,
		description: typing.Optional[str] = None,
		resources: typing.Optional[list] = None,
		**kwargs
	):
		raise NotImplementedError()

	async def get(self, role_id: str) -> dict:
		raise NotImplementedError()

	async def update(
		self,
		role_id: str,
		description: typing.Optional[str] = None,
		resources: typing.Optional[list] = None,
		**kwargs
	):
		raise NotImplementedError()

	async def delete(self, role_id: str):
		raise NotImplementedError()

	def role_tenant_matches(self, role_id: str):
		raise NotImplementedError()