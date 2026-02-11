import re
import pymongo
import pymongo.errors
import secrets
import asab

from .abc import ClientProviderABC


class MongoDBClientProvider(ClientProviderABC):

	Type = "mongodb"

	ConfigDefaults = {
		"mongodb_collection": "cl",
	}

	def __init__(self, app: asab.Application, provider_id: str, config_section_name: str, config: dict | None = None):
		super().__init__(app=app, provider_id=provider_id, config_section_name=config_section_name, config=config)
		self.StorageService = None
		self.CollectionName = self.Config.get("mongodb_collection")


	async def initialize(self, app):
		self.StorageService = app.get_service("asab.StorageService")
		await self._prepare_storage()


	async def _prepare_storage(self):
		# Create index for case-insensitive alphabetical sorting
		coll = await self.StorageService.collection(self.CollectionName)
		await coll.create_index(
			[
				("client_name", pymongo.ASCENDING),
			],
			collation={
				"locale": "en",
				"strength": 1,
			}
		)


	def _build_substring_filter_query(self, substring_filter: str) -> dict:
		return {"$or": [
			{"_id": re.compile(re.escape(substring_filter))},
			{"client_name": re.compile(re.escape(substring_filter), re.IGNORECASE)},
		]}


	async def iterate_clients(
		self,
		page: int = 0,
		limit: int = None,
		substring_filter: str | None = None,
		attribute_filter: dict | None = None,
		sort_by: tuple | None = None,
	):
		coll = await self.StorageService.collection(self.CollectionName)
		query = {}
		if substring_filter:
			query.update(self._build_substring_filter_query(substring_filter))
		if attribute_filter:
			query.update(attribute_filter)
		cursor = coll.find(query)
		if sort_by:
			field, direction = sort_by
			pymongo_dir = pymongo.ASCENDING if direction == "a" else pymongo.DESCENDING
			if field == "client_name":
				cursor = cursor.collation({"locale": "en"})
			cursor = cursor.sort(field, pymongo_dir)
		if limit is not None:
			cursor = cursor.skip(limit * page).limit(limit)
		async for client in cursor:
			yield client


	async def count_clients(
		self,
		substring_filter: str | None = None,
		attribute_filter: dict | None = None,
	) -> int:
		coll = await self.StorageService.collection(self.CollectionName)
		query = {}
		if substring_filter:
			query.update(self._build_substring_filter_query(substring_filter))
		if attribute_filter:
			query.update(attribute_filter)
		return await coll.count_documents(query)


	async def create_client(self, client_id: str | None = None, **client_data) -> str:
		if client_id is None:
			client_id = secrets.token_urlsafe(16)
		upsertor = self.StorageService.upsertor(self.CollectionName, client_id)
		for k, v in client_data.items():
			if v is not None:
				upsertor.set(k, v)
			else:
				upsertor.unset(k)
		client_id = await upsertor.execute()
		return client_id


	async def get_client(self, client_id: str) -> dict:
		client_dict = await self.StorageService.get(self.CollectionName, client_id)
		return client_dict


	async def update_client(self, client_id: str, **client_data):
		try:
			client_stored = await self.get_client(client_id)
		except KeyError as e:
			raise KeyError(client_id) from e

		upsertor = self.StorageService.upsertor(self.CollectionName, client_id, version=client_stored["_v"])
		for k, v in client_data.items():
			if v is not None:
				upsertor.set(k, v)
			else:
				upsertor.unset(k)
		await upsertor.execute()


	async def delete_client(self, client_id: str):
		coll = await self.StorageService.collection(self.CollectionName)
		result = await coll.delete_one({"_id": client_id})
		if result.deleted_count == 0:
			raise KeyError(client_id)
