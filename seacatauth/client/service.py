import hashlib
import logging
import re
import secrets

import asab.storage.exceptions
import asab.exceptions

#

L = logging.getLogger(__name__)

#


class ClientService(asab.Service):

	ClientCollection = "cl"
	ClientIdPattern = r"[a-z][a-z0-9._-]{2,31}"
	ClientSecretLength = 32

	def __init__(self, app, service_name="seacatauth.ClientService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.ClientIdRegex = re.compile("^{}$".format(self.ClientIdPattern))


	async def initialize(self, app):
		await super().initialize(app)
		# TODO: Auto-create clients for Seacat UI etc.


	async def list(self, page: int = 0, limit: int = None, query_filter: dict = None):
		collection = self.StorageService.Database[self.ClientCollection]

		if query_filter is None:
			query_filter = {}
		cursor = collection.find(query_filter)

		cursor.sort("_c", -1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		resources = []
		count = await collection.count_documents(query_filter)
		async for resource_dict in cursor:
			resources.append(resource_dict)

		return {
			"data": resources,
			"count": count,
		}


	async def get(self, client_id: str):
		data = await self.StorageService.get(self.ClientCollection, client_id)
		return data


	async def create(
		self,
		client_id: str,
		base_url: str,
		description: str = None,
		scope: list = None,
	):
		# TODO: Generate client secret
		if self.ClientIdRegex.match(client_id) is None:
			L.error("Invalid ID format", struct_data={"client_id": client_id})
			return {
				"result": "INVALID-VALUE",
				"message":
					"Client ID must consist only of characters 'a-z0-9._-', "
					"start with a letter, and be between 3 and 32 characters long.",
			}

		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id)

		upsertor.set("bu", base_url)  # TODO: Validate

		client_secret = secrets.token_urlsafe(self.ClientSecretLength)
		upsertor.set("c", client_secret)

		if description is not None:
			upsertor.set("d", description)

		if scope is not None:
			upsertor.set("s", scope)  # TODO: Validate

		try:
			await upsertor.execute()
			L.log(asab.LOG_NOTICE, "Client created", struct_data={"client_id": client_id})
		except asab.storage.exceptions.DuplicateError:
			raise asab.exceptions.Conflict(key="id", value=client_id)


	async def update(
		self,
		client_id: str,
		base_url: str = None,
		description: str = None,
		scope: list = None,
	):
		raise NotImplementedError()


	async def delete(self, client_id: str):
		raise NotImplementedError()
