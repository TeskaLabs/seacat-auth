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

	# TODO: Implement support for a list of authorized URIs (alternative to a single base URL)

	def __init__(self, app, service_name="seacatauth.ClientService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.ClientIdRegex = re.compile("^{}$".format(self.ClientIdPattern))


	async def initialize(self, app):
		await super().initialize(app)
		# TODO: Auto-create clients for Seacat UI etc.


	async def list(self, page: int = 0, limit: int = None, query_filter: dict = None, include: list = None):
		collection = self.StorageService.Database[self.ClientCollection]

		if query_filter is None:
			query_filter = {}
		cursor = collection.find(query_filter)

		cursor.sort("_c", -1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		clients = []
		count = await collection.count_documents(query_filter)
		async for data in cursor:
			clients.append(self.normalize_client(data, include))

		return {
			"data": clients,
			"count": count,
		}


	async def get(self, client_id: str, include: list = None):
		data = await self.StorageService.get(self.ClientCollection, client_id)
		return self.normalize_client(data, include)


	def normalize_client(self, data, include):
		return {
			k: v
			for k, v in data
			if not k.startswith("__") or k in include
		}


	async def create(
		self,
		client_id: str,
		base_url: str,
		description: str = None,
		scope: list = None,
	):
		if self.ClientIdRegex.match(client_id) is None:
			L.error("Invalid ID format", struct_data={"client_id": client_id})
			return {
				"result": "INVALID-VALUE",
				"message":
					"OpenIDConnect Client ID must consist only of characters 'a-z0-9._-', "
					"start with a letter, and be between 3 and 32 characters long.",
			}

		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id)

		upsertor.set("bu", base_url)  # TODO: Validate

		client_secret = secrets.token_urlsafe(self.ClientSecretLength)
		# TODO: Encrypt secret
		upsertor.set("__cs", client_secret)

		if description is not None:
			upsertor.set("d", description)

		if scope is not None:
			upsertor.set("s", scope)  # TODO: Validate

		try:
			await upsertor.execute()
			L.log(asab.LOG_NOTICE, "OpenIDConnect Client created", struct_data={"client_id": client_id})
		except asab.storage.exceptions.DuplicateError:
			raise asab.exceptions.Conflict(key="client_id", value=client_id)

		return {
			"client_id": client_id,
			"client_secret": client_secret,
		}


	async def reset_secret(self, client_id: str):
		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id)
		client_secret = secrets.token_urlsafe(self.ClientSecretLength)
		upsertor.set("cs", client_secret)
		return client_secret


	async def update(
		self,
		client_id: str,
		base_url: str = None,
		description: str = None,
		scope: list = None,
	):
		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id)

		if base_url is not None:
			upsertor.set("bu", base_url)  # TODO: Validate

		if description is not None:
			upsertor.set("d", description)

		if scope is not None:
			upsertor.set("s", scope)  # TODO: Validate

		await upsertor.execute()
		L.log(asab.LOG_NOTICE, "OpenIDConnect Client updated", struct_data={"client_id": client_id})


	async def delete(self, client_id: str):
		self.StorageService.delete(self.ClientCollection, client_id)
		L.log(asab.LOG_NOTICE, "OpenIDConnect Client deleted", struct_data={"client_id": client_id})


	async def authorize_client(
		self,
		client_id: str,
		uri: str = None,
		client_secret: str = None,
		scope: list = None,
	):
		try:
			client = await self.get(client_id, include=frozenset(["__cs"]))
		except KeyError:
			L.error("Invalid OpenIDConnect client ID", struct_data={
				"client_id": client_id,
			})
			return False

		if client_secret is not None and client_secret != client["__cs"]:  # TODO: Make secret check obligatory
			L.error("Invalid secret for OpenIDConnect client", struct_data={
				"client_id": client_id,
				"client_secret": client_secret,
			})
			return False

		if uri is not None and not uri.startswith(client["bu"]):  # TODO: Make URI check obligatory
			L.error("OpenIDConnect client not authorized for URI", struct_data={
				"client_id": client_id,
				"uri": uri,
			})
			return False

		if scope is not None:  # TODO: Make scope check obligatory
			for scope_item in scope:
				if scope_item not in client["s"]:
					L.error("OpenIDConnect client not authorized for scope", struct_data={
						"client_id": client_id,
						"scope": scope_item,
					})
					return False

		return True
