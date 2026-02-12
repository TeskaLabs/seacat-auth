import base64
import binascii
import datetime
import logging
import secrets
import typing
import urllib.parse
import asab.storage.exceptions
import asab.exceptions
import asab.utils
import asab.web.auth

from .. import exceptions, AuditLogger
from .. import generic
from ..generic import amerge_sorted
from ..models import Session
from ..models.const import OAuth2, ResourceId
from . import schema
from .provider.abc import ClientProviderABC


L = logging.getLogger(__name__)


CLIENT_DEFAULTS = {
	"token_endpoint_auth_method": OAuth2.TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
	"response_types": [OAuth2.ResponseType.CODE],
	"grant_types": [OAuth2.GrantType.AUTHORIZATION_CODE],
	"application_type": OAuth2.ApplicationType.WEB,
	"redirect_uri_validation_method": OAuth2.RedirectUriValidationMethod.FULL_MATCH,
	"code_challenge_method": OAuth2.CodeChallengeMethod.NONE,
}

TIME_ATTRIBUTES = {"default_max_age", "session_expiration"}


class ClientService(asab.Service):
	"""
	Implements API for OpenID Connect client registration.

	https://openid.net/specs/openid-connect-registration-1_0.html
	"""

	ClientCollection = "cl"
	ClientSecretLength = 32
	ClientIdLength = 16

	def __init__(self, app, service_name="seacatauth.ClientService", create_default_provider=True):
		super().__init__(app, service_name)
		self.OIDCService = None
		self.ClientSecretExpiration = asab.Config.getseconds(
			"seacatauth:client", "client_secret_expiration", fallback=None)
		if self.ClientSecretExpiration <= 0:
			self.ClientSecretExpiration = None

		self.Cache: typing.Optional[typing.Dict[str, typing.Tuple[dict, datetime.datetime]]] = None
		self.CacheExpiration = asab.Config.getseconds("seacatauth:client", "cache_expiration")
		if self.CacheExpiration <= 0:
			# Disable cache
			self.Cache = None
		else:
			self.Cache = {}
			self.CacheExpiration = datetime.timedelta(seconds=self.CacheExpiration)

		# DEV OPTIONS
		# _allow_custom_client_ids
		#   https://www.oauth.com/oauth2-servers/client-registration/client-id-secret/
		#   OAuth recommends that the client_id be a random string so that it is not easily guessable.
		#   Allowing the client to choose their own ID may make the client application more vulnerable.
		#   We decided to enable this by default for the convenience of simplifying the deployment process.
		self._AllowCustomClientID = asab.Config.getboolean(
			"seacatauth:client", "_allow_custom_client_id", fallback=True)
		# _allow_insecure_web_client_uris
		#   Public non-secure http addresses should never be allowed in production environments.
		self._AllowInsecureWebClientURIs = asab.Config.getboolean(
			"seacatauth:client", "_allow_insecure_web_client_uris", fallback=False)

		if not self._AllowCustomClientID:
			schema.CLIENT_METADATA_SCHEMA.pop("preferred_client_id")

		self.ClientProviders: typing.Dict[str, ClientProviderABC] = {}
		self.DefaultProviderId: str | None = None
		if create_default_provider:
			from .provider.mongodb import MongoDBClientProvider
			provider = MongoDBClientProvider(app, provider_id="default")
			self.register_provider(provider, set_default=True)

		app.PubSub.subscribe("Application.tick/600!", self._clear_expired_cache)


	async def initialize(self, app):
		self.OIDCService = app.get_service("seacatauth.OpenIdConnectService")
		for provider in self.ClientProviders.values():
			await provider.initialize(app)


	def register_provider(self, provider: ClientProviderABC, set_default: bool = False):
		if provider.ProviderId in self.ClientProviders:
			raise ValueError("Client provider with ID {!r} is already registered.".format(provider.ProviderId))
		self.ClientProviders[provider.ProviderId] = provider
		if set_default:
			if self.DefaultProviderId is not None:
				raise ValueError("Default client provider is already set to {!r}.".format(self.DefaultProviderId))
			self.DefaultProviderId = provider.ProviderId


	async def iterate_clients(
		self,
		page: int = 0,
		limit: int = None,
		substring_filter: str | None = None,
		attribute_filter: dict | None = None,
		sort_by: typing.Optional[typing.List[tuple]] = None
	):
		iterators = []
		provider_ids = []
		for provider_id, provider in self.ClientProviders.items():
			iterators.append(provider.iterate_clients(
				substring_filter=substring_filter,
				attribute_filter=attribute_filter,
				sort_by=sort_by,
			))
			provider_ids.append(provider_id)

		offset = (page or 0) * (limit or 0)
		async for client, provider_id in amerge_sorted(
			*iterators,
			iter_meta=provider_ids,
			key=lambda c: c.get("client_name", ""),  # TODO: Implement sorting function
			offset=offset,
			limit=limit,
		):
			yield self._normalize_client(provider_id, client)


	async def count_clients(
		self,
		substring_filter: str | None = None,
		attribute_filter: dict | None = None,
	) -> int | None:
		total_count = 0
		for provider in self.ClientProviders.values():
			count = await provider.count_clients(substring_filter, attribute_filter)
			if count is None:
				# Uncountable provider
				total_count = None
			elif total_count is not None:
				total_count += count
		return total_count


	async def get_client(self, client_id: str, use_cache: bool = True):
		"""
		Get client metadata
		"""
		client = await self._get_client_raw(client_id, use_cache)
		provider_id, _ = self.parse_client_id(client_id)
		return self._normalize_client(provider_id, client)


	async def _get_client_raw(self, client_id: str, use_cache: bool = True):
		"""
		Get raw client metadata
		"""
		if use_cache:
			# Try to get client from cache
			client = self._get_from_cache(client_id)
			if client:
				return client

		# Get from the database
		provider_id, internal_client_id = self.parse_client_id(client_id)
		try:
			provider = self.ClientProviders[provider_id]
			client = await provider.get_client(internal_client_id)
		except KeyError:
			raise exceptions.ClientNotFoundError(client_id)
		self._store_in_cache(client_id, client)
		return client


	def parse_client_id(self, client_id: str) -> tuple[str, str]:
		parts = client_id.split(":", 1)
		if len(parts) == 1:
			return self.DefaultProviderId, client_id
		else:
			return parts[0], parts[1]


	def get_editable_provider(self) -> ClientProviderABC:
		default_provider = self.ClientProviders[self.DefaultProviderId]
		if default_provider.Editable:
			return default_provider
		for provider in self.ClientProviders.values():
			if provider.Editable:
				return provider
		raise RuntimeError("No editable client provider is registered.")


	async def create_client(
		self,
		provider_id: str = None,
		*,
		_custom_client_id: str = None,
		**kwargs
	):
		"""
		Register a new OpenID Connect client
		https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration
		"""
		if provider_id:
			if provider_id not in self.ClientProviders:
				raise ValueError("No client provider with ID {!r} is registered.".format(provider_id))
			provider = self.ClientProviders[provider_id]
		else:
			provider = self.get_editable_provider()

		if _custom_client_id is not None:
			client_id = _custom_client_id
			L.warning("Creating a client with custom ID.", struct_data={"client_id": client_id})
		else:
			client_id = secrets.token_urlsafe(self.ClientIdLength)

		client_data = {**CLIENT_DEFAULTS, **kwargs}
		client_data = self._validate_and_normalize_client_update(current=None, update=client_data)
		internal_client_id = await provider.create_client(client_id, **client_data)
		client_id = _build_client_id(provider.ProviderId, internal_client_id)
		L.log(asab.LOG_NOTICE, "Client created.", struct_data={"client_id": client_id})
		return client_id


	def _validate_and_normalize_client_update(self, current: dict | None, update: dict) -> dict:
		client_data = {**(current or {})}
		for k, v in update.items():
			if k not in schema.CLIENT_METADATA_SCHEMA:
				raise asab.exceptions.ValidationError("Unexpected argument: {}".format(k))
			if k in TIME_ATTRIBUTES:
				try:
					v = asab.utils.convert_to_seconds(v)
				except ValueError as e:
					raise asab.exceptions.ValidationError(
						"{!r} must be either a number or a duration string.".format(k)) from e
			if v == "":
				v = None

			client_data[k] = v

		self._check_redirect_uris(**client_data)
		self._check_grant_types(**client_data)
		return client_data


	async def reset_secret(self, client_id: str):
		"""
		Set or reset client secret
		"""
		provider_id, internal_client_id = self.parse_client_id(client_id)
		try:
			provider = self.ClientProviders[provider_id]
			client = await provider.get_client(internal_client_id)
		except KeyError:
			raise exceptions.ClientNotFoundError(client_id)
		assert_client_is_editable(client)

		client_secret, client_secret_expires_at = self._generate_client_secret()
		client_secret_hash = generic.argon2_hash(client_secret)
		update = {
			"__client_secret": client_secret_hash,
			"client_secret_updated_at": datetime.datetime.now(datetime.timezone.utc),
		}
		if client_secret_expires_at is not None:
			update["client_secret_expires_at"] = client_secret_expires_at

		await provider.update_client(internal_client_id, **update)
		AuditLogger.log(asab.LOG_NOTICE, "Client secret updated.", struct_data={"client_id": client_id})
		self._delete_from_cache(client_id)

		return client_secret, client_secret_expires_at


	async def update_client(self, client_id: str, **client_data):
		provider_id, internal_client_id = self.parse_client_id(client_id)
		try:
			provider = self.ClientProviders[provider_id]
			current_client = await provider.get_client(internal_client_id)
		except KeyError:
			raise exceptions.ClientNotFoundError(client_id)
		assert_client_is_editable(current_client)

		client_data = self._validate_and_normalize_client_update(current=current_client, update=client_data)
		await provider.update_client(internal_client_id, **client_data)
		L.log(asab.LOG_NOTICE, "Client updated.", struct_data={"client_id": client_id})
		self._delete_from_cache(client_id)


	async def delete_client(self, client_id: str):
		provider_id, internal_client_id = self.parse_client_id(client_id)
		try:
			provider = self.ClientProviders[provider_id]
			current_client = await provider.get_client(internal_client_id)
		except KeyError:
			raise exceptions.ClientNotFoundError(client_id)
		assert_client_is_editable(current_client)

		await provider.delete_client(internal_client_id)
		L.log(asab.LOG_NOTICE, "Client deleted.", struct_data={"client_id": client_id})
		self._delete_from_cache(client_id)


	async def validate_client_authorize_options(
		self,
		client: dict,
		redirect_uri: str,
		grant_type: str = None,
		response_type: str = None,
	):
		"""
		Verify that the specified authorization parameters are valid for the client.
		"""
		if not self.OIDCService.DisableRedirectUriValidation and not validate_redirect_uri(
			redirect_uri, client["redirect_uris"], client.get("redirect_uri_validation_method")):
			raise exceptions.InvalidRedirectURI(client_id=client["_id"], redirect_uri=redirect_uri)

		if grant_type is not None and grant_type not in client["grant_types"]:
			raise exceptions.ClientError(client_id=client["_id"], grant_type=grant_type)

		if response_type not in client["response_types"]:
			raise exceptions.ClientError(client_id=client["_id"], response_type=response_type)

		return True


	async def authenticate_client_request(self, request) -> dict:
		"""
		Verify client ID and secret.

		Args:
			request: aiohttp.web.Request

		Returns:
			Authenticated client dictionary
		"""
		basic_auth = self._get_credentials_from_authorization_header(request)
		client_id_post, client_secret_post = await self._get_credentials_from_post_data(request)

		# Determine the authentication method
		if basic_auth:
			auth_method = OAuth2.TokenEndpointAuthMethod.CLIENT_SECRET_BASIC
			client_id, client_secret = basic_auth
			# If client_id_post is also present, it must match the one in the Authorization header
			if client_id_post and client_id_post != client_id:
				L.error("Different client ID in Authorization header and in request body.", struct_data={
					"client_id_basic": client_id,
					"client_id_post": client_id_post,
				})
				raise exceptions.ClientAuthenticationError("Client ID mismatch.", client_id=client_id)
			if client_secret_post is not None:
				L.error(
					"Using client_secret_basic and client_secret_post at the same time is not allowed.",
					struct_data={"client_id": client_id}
				)
				raise exceptions.ClientAuthenticationError(
					"Ambiguous client authentication method.", client_id=client_id)

		elif client_id_post:
			client_id = client_id_post
			if client_secret_post:
				auth_method = OAuth2.TokenEndpointAuthMethod.CLIENT_SECRET_POST
				client_secret = client_secret_post
			else:
				# Public client - Secret not used
				auth_method = OAuth2.TokenEndpointAuthMethod.NONE
				client_secret = None

		else:
			L.error("No client ID in request.")
			raise exceptions.ClientAuthenticationError("No client ID in request.")

		# Get provider and client data
		provider_id, internal_client_id = self.parse_client_id(client_id)
		try:
			provider = self.ClientProviders[provider_id]
			client_dict = await provider.get_client(internal_client_id)
		except KeyError:
			raise exceptions.ClientNotFoundError(client_id)

		# Check if used authentication method matches the pre-configured one
		expected_auth_method = client_dict.get(
			"token_endpoint_auth_method",
			OAuth2.TokenEndpointAuthMethod.CLIENT_SECRET_BASIC
		)
		if auth_method != expected_auth_method:
			L.error("Unexpected client authentication method.", struct_data={
				"received_auth_method": auth_method,
				"expected_auth_method": expected_auth_method,
			})
			raise exceptions.ClientAuthenticationError(
				"Unexpected authentication method (expected {!r}, got {!r}).".format(
					expected_auth_method, auth_method),
				client_id=client_id,
			)

		if auth_method == "none":
			# Public client - no secret verification required
			return client_dict

		# Check secret expiration
		client_secret_expires_at = client_dict.get("client_secret_expires_at", None)
		if client_secret_expires_at and client_secret_expires_at < datetime.datetime.now(datetime.timezone.utc):
			L.error("Expired client secret.", struct_data={"client_id": client_id})
			raise exceptions.ClientAuthenticationError("Expired client secret.", client_id=client_id)

		# Verify client secret
		client_secret_hash = client_dict.get("__client_secret", None)
		if not client_secret_hash:
			L.error("Client does not have a secret set.", struct_data={"client_id": client_id})
			raise exceptions.ClientAuthenticationError("Client does not have a secret set.", client_id=client_id)
		if not generic.argon2_verify(client_secret_hash, client_secret):
			L.error("Incorrect client secret.", struct_data={"client_id": client_id})
			raise exceptions.ClientAuthenticationError("Incorrect client secret.", client_id=client_id)

		return client_dict


	@asab.web.auth.require(ResourceId.CLIENT_APIKEY_MANAGE)
	async def issue_token(
		self,
		client_id: str,
		tenant: str,
		expires_at: typing.Optional[datetime.datetime] = None,
		label: typing.Optional[str] = None,
		**kwargs
	) -> dict:
		"""
		Issue a new access token for a client (=create a session)

		Args:
			client_id: Client ID
			tenant: Tenant scope
			expires_at: Token expiration datetime

		Returns:
			Dictionary with token id, value, expiration and resources
		"""
		authz = asab.contextvars.Authz.get()
		oidc_service = self.App.get_service("seacatauth.OpenIdConnectService")
		scope = []
		if tenant is not None:
			# Verify that the agent has access to the requested tenant
			with asab.contextvars.tenant_context(tenant):
				authz.require_tenant_access()
			scope.append("tenant:{}".format(tenant))

		# Ensure client exists
		await self.get_client(client_id)

		try:
			tokens = await oidc_service.issue_token_for_client_credentials(
				client_id=client_id,
				scope=scope,
				expiration=expires_at,
				label=label,
			)
		except exceptions.OAuth2InvalidScope:
			raise exceptions.TenantAccessDeniedError(tenant)

		session = tokens["session"]

		token_response = {
			"_id": session.Session.Id,
			"token": tokens["access_token"],
			"label": session.Session.Label,
			"exp": session.Session.Expiration,
			"resources": session.Authorization.Authz,
		}
		return token_response


	@asab.web.auth.require(ResourceId.CLIENT_APIKEY_MANAGE)
	async def list_tokens(self, client_id: str):
		"""
		List client tokens (sessions)
		"""
		credentials = await self._get_seacatauth_credentials(client_id)
		session_service = self.App.get_service("seacatauth.SessionService")
		tokens = []
		for session in (await session_service.list(query_filter={
			Session.FN.Credentials.Id: credentials["_id"]
		}))["data"]:
			token = {
				"_id": session["_id"],
				"exp": session["expiration"],
				"resources": session["resources"],
			}
			if "label" in session:
				token["label"] = session["label"]
			tokens.append(token)
		return tokens


	@asab.web.auth.require(ResourceId.CLIENT_APIKEY_MANAGE)
	async def revoke_token(self, client_id: str, session_id: str):
		"""
		Revoke client token by its ID. This is essentially just deleting a session.
		"""
		credentials = await self._get_seacatauth_credentials(client_id)
		session_service = self.App.get_service("seacatauth.SessionService")
		session = await session_service.get(session_id)
		assert session.Credentials.Id == credentials["_id"]
		assert session.OAuth2.ClientId == client_id
		await session_service.delete(session_id)


	@asab.web.auth.require(ResourceId.CLIENT_APIKEY_MANAGE)
	async def revoke_all_tokens(self, client_id: str):
		credentials = await self._get_seacatauth_credentials(client_id)
		session_service = self.App.get_service("seacatauth.SessionService")
		await session_service.delete_sessions_by_credentials_id(credentials["_id"])


	async def _get_seacatauth_credentials(self, client_id: str):
		credentials_service = self.App.get_service("seacatauth.CredentialsService")
		cred_provider = credentials_service.CredentialProviders.get("client")
		return await cred_provider.get_by_client_id(client_id)


	def _get_credentials_from_authorization_header(
		self, request
	) -> typing.Optional[typing.Tuple[str, str]]:
		auth_header = request.headers.get("Authorization")
		if not auth_header:
			return None
		try:
			token_type, auth_token = auth_header.split(" ")
		except ValueError:
			return None
		if token_type != "Basic":
			return None
		try:
			auth_token_decoded = base64.urlsafe_b64decode(auth_token.encode("ascii")).decode("ascii")
		except (binascii.Error, UnicodeDecodeError):
			return None
		try:
			client_id, client_secret = auth_token_decoded.split(":")
		except ValueError:
			return None
		return client_id, client_secret


	async def _get_credentials_from_post_data(
		self, request
	) -> typing.Tuple[typing.Optional[str], typing.Optional[str]]:
		post_data = await request.post()
		return post_data.get("client_id"), post_data.get("client_secret")


	def _check_grant_types(
		self,
		grant_types,
		response_types,
		**kwargs
	):
		# https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
		# The following table lists the correspondence between response_type values that the Client will use
		# and grant_type values that MUST be included in the registered grant_types list:
		# 	code: authorization_code
		# 	id_token: implicit
		# 	token id_token: implicit
		# 	code id_token: authorization_code, implicit
		# 	code token: authorization_code, implicit
		# 	code token id_token: authorization_code, implicit
		if OAuth2.ResponseType.CODE in response_types and OAuth2.GrantType.AUTHORIZATION_CODE not in grant_types:
			raise asab.exceptions.ValidationError(
				"Response type 'code' requires 'authorization_code' to be included in grant types")
		if "id_token" in response_types and "implicit" not in grant_types:
			raise asab.exceptions.ValidationError(
				"Response type 'id_token' requires 'implicit' to be included in grant types")
		if "token" in response_types and "implicit" not in grant_types:
			raise asab.exceptions.ValidationError(
				"Response type 'token' requires 'implicit' to be included in grant types")


	def _check_redirect_uris(
		self,
		redirect_uris: list,
		application_type: str,
		grant_types: list,
		client_uri: str = None,
		**kwargs
	):
		"""
		Check if the redirect URIs can be registered for the given application type

		https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
		"""
		for uri in redirect_uris:
			parsed = urllib.parse.urlparse(uri)
			if len(parsed.netloc) == 0 or len(parsed.scheme) == 0 or len(parsed.fragment) != 0:
				raise asab.exceptions.ValidationError(
					"Redirect URI must be an absolute URI without a fragment component.")

			if application_type == "web":
				if "implicit" in grant_types:
					if parsed.scheme != "https" and not self._AllowInsecureWebClientURIs:
						raise asab.exceptions.ValidationError(
							"Web Clients using the OAuth Implicit Grant Type MUST only register URLs "
							"using the https scheme as redirect_uris.")
					if parsed.hostname == "localhost":
						raise asab.exceptions.ValidationError(
							"Web Clients using the OAuth Implicit Grant Type MUST NOT use localhost as the hostname.")
			elif application_type == "native":
				# TODO: Authorization Servers MAY place additional constraints on Native Clients.
				if parsed.scheme == "http":
					if parsed.hostname == "localhost":
						# This is valid
						pass
					else:
						# Authorization Servers MAY reject Redirection URI values using the http scheme,
						# other than the localhost case for Native Clients.
						raise asab.exceptions.ValidationError(
							"Native Clients MUST only register redirect_uris using custom URI schemes "
							"or URLs using the http scheme with localhost as the hostname.")
				elif parsed.scheme == "https":
					raise asab.exceptions.ValidationError(
						"Native Clients MUST only register redirect_uris using custom URI schemes "
						"or URLs using the http scheme with localhost as the hostname.")
				else:
					# TODO: Proper support for custom URI schemes
					raise asab.exceptions.ValidationError(
						"Support for custom URI schemes has not been implemented yet.")


	def _generate_client_secret(self):
		client_secret = secrets.token_urlsafe(self.ClientSecretLength)
		if self.ClientSecretExpiration is not None:
			client_secret_expires_at = \
				datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=self.ClientSecretExpiration)
		else:
			client_secret_expires_at = None
		return client_secret, client_secret_expires_at


	def _get_from_cache(self, client_id: str):
		if self.Cache is None:
			return None
		if client_id not in self.Cache:
			return None
		client, expires_at = self.Cache[client_id]
		if datetime.datetime.now(datetime.UTC) > expires_at:
			del self.Cache[client_id]
			return None
		return client


	def _store_in_cache(self, client_id, client):
		if self.Cache is None:
			return
		self.Cache[client_id] = (
			client,
			datetime.datetime.now(datetime.UTC) + self.CacheExpiration
		)


	def _delete_from_cache(self, client_id: str):
		if self.Cache is None:
			return
		if client_id in self.Cache:
			del self.Cache[client_id]


	def _clear_expired_cache(self, event_name):
		if not self.Cache:
			return
		valid = {}
		now = datetime.datetime.now(datetime.UTC)
		for k, (v, exp) in self.Cache.items():
			if now < exp:
				valid[k] = v, exp
		self.Cache = valid


	def _normalize_client(self, provider_id: str, raw_client: dict):
		client = {
			k: v
			for k, v in raw_client.items()
			if not k.startswith("_") or k in {"_id", "_v", "_c", "_m"}
		}
		client["_id"] = client["client_id"] = _build_client_id(provider_id, client["_id"])
		client = _set_cookie_name(self.App, client)
		client = _set_credentials_id(self.App, client)
		if "read_only" not in client and client.get("managed_by"):
			client["read_only"] = True
		if "__client_secret" in raw_client:
			client["client_secret"] = True
		return client


def validate_redirect_uri(redirect_uri: str, registered_uris: list, validation_method: str = "full_match"):
	if validation_method is None:
		validation_method = "full_match"

	if validation_method == "full_match":
		# Redirect URI must exactly match one of the registered URIs
		if redirect_uri in registered_uris:
			return True
	elif validation_method == "prefix_match":
		# Redirect URI must start with one of the registered URIs and their netloc must match
		for registered_uri in registered_uris:
			if redirect_uri == registered_uri:
				return True
			if redirect_uri.startswith(registered_uri):
				redirect_uri_parsed = urllib.parse.urlparse(redirect_uri)
				registered_uri_parsed = urllib.parse.urlparse(registered_uri)
				if redirect_uri_parsed.netloc == registered_uri_parsed.netloc:
					return True
	elif validation_method == "none":
		# No validation
		return True
	else:
		raise ValueError("Unsupported redirect_uri_validation_method: {!r}".format(validation_method))

	return False


def is_client_confidential(client: dict):
	token_endpoint_auth_method = client.get("token_endpoint_auth_method", OAuth2.TokenEndpointAuthMethod.NONE)
	if token_endpoint_auth_method not in OAuth2.TokenEndpointAuthMethod:
		raise NotImplementedError("Unsupported token_endpoint_auth_method: {!r}".format(token_endpoint_auth_method))

	if token_endpoint_auth_method == OAuth2.TokenEndpointAuthMethod.NONE:
		return False
	else:
		return True


def assert_client_is_editable(client: dict):
	if client.get("read_only") or client.get("managed_by") is not None:
		L.log(asab.LOG_NOTICE, "Client is not editable.", struct_data={"client_id": client["_id"]})
		raise exceptions.NotEditableError("Client is not editable.")
	return True


def _validate_client_attributes(client_dict: dict):
	"""
	Validate client attributes.
	"""
	for k, v in client_dict.items():
		if k not in schema.CLIENT_METADATA_SCHEMA:
			raise asab.exceptions.ValidationError("Unexpected attribute: {!r}".format(k))

		if k == "grant_types":
			for grant_type in v:
				if grant_type not in OAuth2.GrantType:
					raise asab.exceptions.ValidationError("Invalid grant_type: {!r}".format(grant_type))

		elif k == "response_types":
			for response_type in v:
				if response_type not in OAuth2.ResponseType:
					raise asab.exceptions.ValidationError("Invalid response_type: {!r}".format(response_type))

		elif k == "application_type":
			if v not in OAuth2.ApplicationType:
				raise asab.exceptions.ValidationError("Invalid application_type: {!r}".format(v))

		elif k == "token_endpoint_auth_method":
			if v not in OAuth2.TokenEndpointAuthMethod:
				raise asab.exceptions.ValidationError("Invalid token_endpoint_auth_method: {!r}".format(v))

		elif k == "redirect_uri_validation_method":
			if v not in OAuth2.RedirectUriValidationMethod:
				raise asab.exceptions.ValidationError("Invalid redirect_uri_validation_method: {!r}".format(v))


def _set_credentials_id(app, client: dict) -> dict:
	if client.get("seacatauth_credentials") is not True:
		return client
	credentials_service = app.get_service("seacatauth.CredentialsService")
	if not credentials_service:
		return client
	provider = credentials_service.CredentialProviders.get("client")
	if not provider:
		return client
	client["credentials_id"] = provider._format_credentials_id(client["_id"])
	return client


def _set_cookie_name(app, client: dict) -> dict:
	cookie_svc = app.get_service("seacatauth.CookieService")
	client["cookie_name"] = cookie_svc.get_cookie_name(client["_id"])
	return client


def _build_client_id(provider_id: str, internal_client_id: str) -> str:
	return "{}:{}".format(provider_id, internal_client_id)
