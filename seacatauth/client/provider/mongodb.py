import re
import pymongo
import pymongo.errors
import secrets
import asab
import logging

from .abc import ClientProviderABC


L = logging.getLogger(__name__)


class MongoDBClientProvider(ClientProviderABC):

	Type = "mongodb"

	ConfigDefaults = {
		"mongodb_collection": "cl",
		"editable": True,
	}

	def __init__(self, app: asab.Application, provider_id: str, config: dict | None = None):
		super().__init__(app=app, provider_id=provider_id, config=config)
		self.StorageService = None
		self.CollectionName = self.Config.get("mongodb_collection")
		self.Editable = self.Config.getboolean("editable")


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
		substring_filter: str | None = None,
		attribute_filter: dict | None = None,
		sort_by: list[tuple[str, str]] | None = None,
	):
		coll = await self.StorageService.collection(self.CollectionName)
		query = self._build_query(attribute_filter, substring_filter)
		cursor = coll.find(query)
		if not sort_by:
			# Default sort by client_name ascending
			field, direction = "client_name", "a"
		else:
			if len(sort_by) > 1:
				L.warning(
					"Multiple sort fields are not supported, only the first one will be used",
					struct_data={"sort_by": sort_by}
				)
			field, direction = sort_by[0]
		pymongo_dir = pymongo.ASCENDING if direction == "a" else pymongo.DESCENDING
		if field == "client_name":
			cursor = cursor.collation({"locale": "en"})
		cursor = cursor.sort(field, pymongo_dir)
		async for client_dict in cursor:
			self._add_provider_attributes(client_dict)
			yield client_dict


	async def count_clients(
		self,
		substring_filter: str | None = None,
		attribute_filter: dict | None = None,
	) -> int:
		coll = await self.StorageService.collection(self.CollectionName)
		query = self._build_query(attribute_filter, substring_filter)
		return await coll.count_documents(query)

	def _build_query(self, attribute_filter: dict, substring_filter: str) -> dict:
		query = {}
		filters = []
		if substring_filter:
			filters.append(self._build_substring_filter_query(substring_filter))
		if attribute_filter:
			filters.append(attribute_filter)
		if filters:
			query["$and"] = filters
		return query


	async def create_client(self, client_id: str | None = None, **client_data) -> str:
		if not self.Editable:
			raise RuntimeError("Provider is not editable")
		if client_id is None:
			client_id = secrets.token_urlsafe(16)
		upsertor = self.StorageService.upsertor(self.CollectionName, client_id, version=0)
		for k, v in client_data.items():
			if v is not None:
				upsertor.set(k, v)
			else:
				upsertor.unset(k)
		client_id = await upsertor.execute()
		return client_id


	async def get_client(self, client_id: str) -> dict:
		client_dict = await self.StorageService.get(self.CollectionName, client_id)
		client_dict = self._add_provider_attributes(client_dict)
		return client_dict


	async def update_client(self, client_id: str, **client_data):
		if not self.Editable:
			raise RuntimeError("Provider is not editable")
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
		if not self.Editable:
			raise RuntimeError("Provider is not editable")
		coll = await self.StorageService.collection(self.CollectionName)
		result = await coll.delete_one({"_id": client_id})
		if result.deleted_count == 0:
			raise KeyError(client_id)


	def _add_provider_attributes(self, client_dict: dict) -> dict:
		client_dict["_provider_id"] = self.ProviderId
		client_dict["read_only"] = not self.Editable
		return client_dict
