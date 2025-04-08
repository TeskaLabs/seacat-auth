import logging
import re
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

	Type = "client"
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
		client_service = self.App.get_service("seacatauth.ClientService")
		try:
			client_id = self._format_object_id(credentials_id)
		except ValueError:
			raise exceptions.CredentialsNotFoundError(credentials_id)

		try:
			client = await client_service.get(client_id)
		except KeyError:
			raise exceptions.CredentialsNotFoundError(credentials_id)

		return self._normalize_credentials(client)


	async def count(self, filtr: str = None) -> int:
		client_service = self.App.get_service("seacatauth.ClientService")
		return await client_service.count(query_filter=filtr)


	async def search(self, filter: str = None, sort: dict = None, page: int = 0, limit: int = 0) -> list:
		client_service = self.App.get_service("seacatauth.ClientService")
		data = []
		async for client in client_service.iterate(page, limit, filter):
			data.append(self._normalize_credentials(client))
		return data


	async def iterate(self, offset: int = 0, limit: int = None, filtr: str = None):
		client_service = self.App.get_service("seacatauth.ClientService")
		async for credentials in client_service.iterate(
			page=offset // limit if limit else 0,
			limit=limit,
			query_filter=filtr
		):
			yield self._normalize_credentials(credentials)


	def _build_filter(self, id_filter: str) -> dict:
		if id_filter:
			return {
				"_id": re.compile("^{}".format(re.escape(id_filter)))
			}
		else:
			return {}


	def _normalize_credentials(self, db_obj, include=None) -> dict:
		return {
			"_id": self._format_credentials_id(db_obj["_id"]),
			"_type": self.Type,
			"_provider_id": self.ProviderID,
			"client_id": db_obj["_id"],
			"label": db_obj["client_name"] or db_obj["_id"],
		}
