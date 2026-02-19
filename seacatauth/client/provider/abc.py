import abc
import typing

import asab


class ClientProviderABC(asab.Configurable, abc.ABC):
	"""
	Abstract base class for client providers in the SeaCat Auth system.

	ClientProviderABC defines the interface for all client providers, which are responsible for managing client records
	(such as OAuth2/OIDC clients) in various backends. Providers must implement methods for iterating, counting,
	retrieving, creating, updating, and deleting client records.

	Expected Client Dictionary Attributes:
	-------------------------------------
	Each client is represented as a dictionary with attributes defined by the CLIENT_METADATA_SCHEMA (see schema.py)
	plus additional storage-related and custom attributes.
	For the client to be a valid object, it must have at least a unique _id.
	Additional attributes are required for OAuth2/OIDC functionality, such as redirect_uris for authorization code flow.

	Storage-related attributes:
		- _id: str
			REQUIRED Unique identifier of the client record in the storage backend.
		- _c: datetime | None
			Creation timestamp of the client record. Used as the value of client_id_issued_at.
		- _m: datetime | None
			Last modification timestamp of the client record.
		- _v: int | None
			Version of the client record, used for optimistic concurrency control.
		- managed_by: str | None
			The owner or manager of the client record, used for access control and auditing purposes.
			Any non-empty value indicates that the client should not be modified by the admin UI.

	Canonical OAuth2/OIDC attributes:
		- client_name: str | None
			Name of the client to be presented to the end-user.
		- client_uri: str | None
			URL of the home page of the client.
		- redirect_uris: list[str] | None
			Array of redirection URI values used by the client.
		- application_type: str | None
			Kind of the application (e.g., 'web').
		- response_types: list[str] | None
			List of OAuth 2.0 response_type values (e.g., ['code']).
		- grant_types: list[str] | None
			List of OAuth 2.0 grant types (e.g., ['authorization_code']).
		- token_endpoint_auth_method: str | None
			Client authentication method for the token endpoint.
		- default_max_age: int | str | None
			Default maximum authentication age (seconds or time-unit string).
		- code_challenge_method: str | None
			Code challenge method for PKCE (e.g., 'S256').
		- redirect_uri_validation_method: str | None
			Method for validating redirect URIs.

	OAuth2 client secret:
		- __client_secret: str | None
			Hashed client secret for confidential clients. Not included in REST API responses, only used internally for
			authentication and credential management.
		- client_secfret_issued_at: datetime | None
			Timestamp of when the client secret was issued.
		- client_secret_expires_at: datetime | None
			When the client secret expires. A value of 0 or None means it does not expire.

	SeaCat Auth custom/non-canonical attributes:
		- cookie_domain: str | None
			Domain of the client cookie. Defaults to the application's global cookie domain.
		- cookie_webhook_uri: str | None
			Webhook URI for setting additional custom cookies at the cookie entrypoint. It must be a back-channel
			URI and accept a JSON PUT request and respond with a JSON object of cookies to set.
		- cookie_entry_uri: str | None
			Public URI of the client's cookie entrypoint.
		- authorize_uri: str | None
			URL of OAuth authorize endpoint. Useful when logging in from different than the default domain.
		- login_uri: str | None
			URL of preferred login page.
		- authorize_anonymous_users: bool | None
			Allow authorize requests with anonymous users.
		- anonymous_cid: str | None
			ID of credentials for authenticating anonymous sessions.
		- session_expiration: int | None
			Client session expiration in seconds.
		- seacatauth_credentials: bool | None
			Whether to create client credentials for this client and enable access control.

	Additional fields may be present depending on the provider implementation and application needs.
	"""

	Type = None
	Editable = False

	def __init__(self, app: asab.Application, provider_id: str, config: dict | None = None):
		config_section_name = "seacatauth:client:{}:{}".format(self.Type, provider_id)
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
