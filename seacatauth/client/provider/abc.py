import abc
import typing

import asab


class ClientProviderABC(asab.Configurable, abc.ABC):

	Type = None
	Editable = False

	def __init__(self, app: asab.Application, provider_id: str, config: dict | None = None):
		config_section_name = "seacatauth:client:{}".format(provider_id)
		super().__init__(config_section_name=config_section_name, config=config)
		self.App = app
		self.ProviderId = provider_id


	async def initialize(self, app):
		"""
		Initialize provider. This is called by ClientService after all providers are registered.
		"""
		pass


	@abc.abstractmethod
	async def iterate_clients(
		self,
		substring_filter: str | None = None,
		attribute_filter: dict | None = None,
		sort_by: list[tuple[str, str]] | None = None,
	) -> typing.AsyncIterable[dict]:
		"""
		Iterate clients.

		Args:
			page: Page number (starting from 0)
			limit: Number of clients per page. If None, return all clients.
			substring_filter: Substring to filter clients by ID or name. If None, no filtering is applied.
			attribute_filter: Dictionary of attribute filters. Only clients matching all provided attributes will be returned.
				If None, no filtering is applied.
			sort_by: Tuple of (field_name, direction), where direction is "a" or "d". If None, no sorting is applied.

		Returns:
			An async iterable of client dictionaries.
		"""
		raise NotImplementedError()


	@abc.abstractmethod
	async def count_clients(
		self,
		substring_filter: str | None = None,
		attribute_filter: dict | None = None,
	) -> int | None:
		"""
		Count clients.

		Args:
			substring_filter: Substring to filter clients by ID or name. If None, no filtering is applied.
			attribute_filter: Dictionary of attribute filters. Only clients matching all provided attributes will be counted.
				If None, no filtering is applied.

		Returns:
			The number of clients matching the filters, or None if counting is not supported.
		"""
		raise NotImplementedError()


	@abc.abstractmethod
	async def get_client(
		self,
		client_id: str,
	) -> dict:
		"""
		Get client data by client ID.

		Args:
			client_id: The ID of the client to retrieve.

		Returns:
			A dictionary of client data.

		Raises:
			KeyError: If a client with the given ID does not exist.
		"""
		raise NotImplementedError()


	async def create_client(
		self,
		client_id: str | None = None,
		**client_data,
	) -> str:
		"""
		Create a new client with the given data. Return the new client's ID.

		Args:
			client_id: Optional client ID. If None, a new ID will be generated.
			**client_data: Arbitrary client data to store.

		Returns:
			The ID of the created client.

		Raises:
			asab.storage.exceptions.DuplicateError: If a client with the same ID already exists.
		"""
		raise NotImplementedError()


	async def update_client(
		self,
		client_id: str,
		**client_data,
	):
		"""
		Update client data by client ID.

		Args:
			client_id: The ID of the client to update.
			**client_data: Arbitrary client data to update. Only provided fields will be updated.
				To remove a field, set its value to None.

		Raises:
			KeyError: If a client with the given ID does not exist.
		"""
		raise NotImplementedError()


	async def delete_client(
		self,
		client_id: str,
	):
		"""
		Delete a client by client ID.

		Args:
			client_id: The ID of the client to delete.

		Raises:
			KeyError: If a client with the given ID does not exist.
		"""
		raise NotImplementedError()
