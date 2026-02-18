import logging
import typing
import asab.storage.exceptions

from .abc import CredentialsProviderABC
from ... import exceptions


L = logging.getLogger(__name__)


class ClientCredentialsService(asab.Service):

	def __init__(self, app, service_name="seacatauth.ClientCredentialsService"):
		super().__init__(app, service_name)

	def create_provider(self):
		return ClientCredentialsProvider(self.App)


class ClientCredentialsProvider(CredentialsProviderABC):
	"""
	Adapter for ClientService that acts as a credentials provider.
	This allows for assigning tenants and roles to clients.
	"""

	Type = "seacatauth"
	ConfigDefaults = {
		"order": "100",
	}

	def __init__(
		self,
		app,
		provider_id="client",
		config_section_name="seacatauth:credentials:client",
	):
		super().__init__(app, provider_id, config_section_name)


	async def get(self, credentials_id, include=None) -> typing.Optional[dict]:
		try:
			client_id = self._format_object_id(credentials_id)
		except ValueError:
			raise exceptions.CredentialsNotFoundError(credentials_id)

		return await self.get_by_client_id(client_id, include=include)


	async def count(self, filtr: str = None) -> int:
		client_service = self.App.get_service("seacatauth.ClientService")
		return await client_service.count_clients(query_filter=self._build_filter(filtr))


	async def search(self, filter: str = None, sort: dict = None, page: int = 0, limit: int = 0) -> list:
		client_service = self.App.get_service("seacatauth.ClientService")
		data = []
		async for client in client_service.iterate_clients(page, limit, self._build_filter(filter)):
			data.append(self._normalize_credentials(client))
		return data


	async def iterate(self, offset: int = 0, limit: int = None, filtr: str = None):
		client_service = self.App.get_service("seacatauth.ClientService")
		async for credentials in client_service.iterate_clients(
			page=offset // limit if limit else 0,
			limit=limit,
			query_filter=self._build_filter(filtr),
		):
			yield self._normalize_credentials(credentials)


	def format_credentials_id(self, client_id: str) -> str:
			return self._format_credentials_id(client_id)


	async def get_by_client_id(self, client_id: str, include=None) -> dict:
		client_service = self.App.get_service("seacatauth.ClientService")
		credentials_id = self._format_credentials_id(client_id)
		try:
			client = await client_service.get_client(client_id)
		except KeyError as e:
			raise exceptions.CredentialsNotFoundError(credentials_id) from e

		if client.seacatauth_credentials is not True:
			L.debug("Client does not have SeaCat Auth credentials enabled.", struct_data={"client_id": client_id})
			raise exceptions.CredentialsNotFoundError(credentials_id)

		return self._normalize_credentials(client, include)


	def _build_filter(self, id_filter: str) -> dict:
		client_service = self.App.get_service("seacatauth.ClientService")
		if id_filter:
			return {"$and": [
				{"seacatauth_credentials": True},
				client_service.build_filter(id_filter),
			]}
		else:
			return {"seacatauth_credentials": True}


	def _normalize_credentials(self, db_obj, include=None) -> dict:
		return {
			"_id": self._format_credentials_id(db_obj["_id"]),
			"_type": self.Type,
			"_c": db_obj["_c"],
			"_m": db_obj["_m"],
			"_v": db_obj["_v"],
			"_provider_id": self.ProviderID,
			"client_id": db_obj["_id"],
			"label": db_obj["client_name"] or db_obj["_id"],
			"username": db_obj["_id"],  # TODO: Temporary fallback for the UI
		}
