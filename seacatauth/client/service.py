import base64
import binascii
import dataclasses
import datetime
import logging
import re
import secrets
import typing
import urllib.parse
import asab.storage.exceptions
import asab.exceptions
import pymongo
import asab.utils
import asab.web.auth

from .. import exceptions
from .. import generic
from ..events import EventTypes
from ..models import Session
from ..models.const import OAuth2, ResourceId
from ..models.client import Client
from . import schema


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

	def __init__(self, app, service_name="seacatauth.ClientService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
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

		app.PubSub.subscribe("Application.tick/600!", self._clear_expired_cache)


	async def initialize(self, app):
		self.OIDCService = app.get_service("seacatauth.OpenIdConnectService")

		# Create index for case-insensitive alphabetical sorting
		coll = await self.StorageService.collection(self.ClientCollection)
		await coll.create_index(
			[
				("client_name", pymongo.ASCENDING),
			],
			collation={
				"locale": "en",
				"strength": 1,
			}
		)


	def build_filter(self, match_string: str) -> dict:
		return {"$or": [
			{"_id": re.compile("^{}".format(re.escape(match_string)))},
			{"client_name": re.compile(re.escape(match_string), re.IGNORECASE)},
		]}


	async def iterate_clients(
		self,
		page: int = 0,
		limit: int = None,
		query_filter: typing.Optional[str | typing.Dict] = None,
		sort_by: typing.Optional[typing.List[tuple]] = None
	):
		collection = self.StorageService.Database[self.ClientCollection]

		if query_filter is None:
			query_filter = {}
		elif isinstance(query_filter, str):
			query_filter = self.build_filter(query_filter)
		cursor = collection.find(query_filter)

		if sort_by:
			if len(sort_by) > 1:
				L.warning("Multiple sorting parameters are not supported. Only the first one is taken into account.")
			sort_by = sort_by[0]

			if sort_by[0] == "client_name":
				# Case-insensitive sorting
				cursor.collation({"locale": "en"})
			cursor.sort(*sort_by)

		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		async for client in cursor:
			yield self._deserialize_client(client)


	async def count_clients(self, query_filter: typing.Optional[str | typing.Dict] = None):
		collection = self.StorageService.Database[self.ClientCollection]
		if query_filter is None:
			query_filter = {}
		elif isinstance(query_filter, str):
			query_filter = self.build_filter(query_filter)
		return await collection.count_documents(query_filter)


	async def get_client(self, client_id: str, normalize: bool = True) -> Client:
		"""
		Get client metadata
		"""
		# Try to get client from cache
		client = self._get_from_cache(client_id)
		if client:
			return client

		# Get from the database
		client = await self.StorageService.get(self.ClientCollection, client_id)
		client = self._deserialize_client(client)
		self._store_in_cache(client_id, client)
		return client


	async def create_client(
		self, *,
		_custom_client_id: str = None,
		**kwargs
	):
		"""
		Register a new OpenID Connect client
		https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration
		"""
		if _custom_client_id is not None:
			client_id = _custom_client_id
			L.warning("Creating a client with custom ID.", struct_data={"client_id": client_id})
		else:
			client_id = secrets.token_urlsafe(self.ClientIdLength)
		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id)

		client_metadata = {**CLIENT_DEFAULTS, **kwargs}
		self._check_redirect_uris(**client_metadata)
		self._check_grant_types(**client_metadata)

		for k in schema.CLIENT_METADATA_SCHEMA:
			v = client_metadata.get(k)
			if v is None or (isinstance(v, str) and len(v) == 0):
				continue
			if k in TIME_ATTRIBUTES:
				try:
					v = asab.utils.convert_to_seconds(v)
				except ValueError as e:
					raise asab.exceptions.ValidationError(
						"{!r} must be either a number or a duration string.".format(k)) from e
			upsertor.set(k, v)

		try:
			await upsertor.execute(event_type=EventTypes.CLIENT_REGISTERED)

		except asab.storage.exceptions.DuplicateError:
			raise asab.exceptions.Conflict(key="client_id", value=client_id)

		L.log(asab.LOG_NOTICE, "Client created.", struct_data={"client_id": client_id})
		return client_id


	async def reset_secret(self, client_id: str):
		"""
		Set or reset client secret
		"""
		# TODO: Use M2M credentials provider.
		client = await self.get_client(client_id)
		assert_client_is_editable(client)
		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id, version=client["_v"])
		client_secret, client_secret_expires_at = self._generate_client_secret()
		client_secret_hash = generic.argon2_hash(client_secret)
		upsertor.set("__client_secret", client_secret_hash)
		if client_secret_expires_at is not None:
			upsertor.set("client_secret_expires_at", client_secret_expires_at)

		upsertor.set("client_secret_updated_at", datetime.datetime.now(datetime.timezone.utc))

		await upsertor.execute(event_type=EventTypes.CLIENT_SECRET_RESET)
		self._delete_from_cache(client_id)
		L.log(asab.LOG_NOTICE, "Client secret updated.", struct_data={"client_id": client_id})

		return client_secret, client_secret_expires_at


	async def update_client(self, client_id: str, **kwargs):
		client = await self.get_client(client_id, normalize=False)
		assert_client_is_editable(client)
		client_update = {
			k: v
			for k, v in client.items()
			if (
				k in schema.CLIENT_METADATA_SCHEMA
				and not k.startswith("_")
			)
		}
		client_update.update(kwargs)

		self._check_redirect_uris(**client_update)
		self._check_grant_types(**client_update)

		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id, version=client["_v"])

		for k, v in client_update.items():
			if k not in schema.CLIENT_METADATA_SCHEMA:
				raise asab.exceptions.ValidationError("Unexpected argument: {}".format(k))

			if v is None or (isinstance(v, str) and len(v) == 0):
				upsertor.unset(k,)
				continue

			if k in TIME_ATTRIBUTES:
				try:
					v = asab.utils.convert_to_seconds(v)
				except ValueError as e:
					raise asab.exceptions.ValidationError(
						"{!r} must be either a number or a duration string.".format(k)) from e
			upsertor.set(k, v)

		await upsertor.execute(event_type=EventTypes.CLIENT_UPDATED)
		self._delete_from_cache(client_id)
		L.log(asab.LOG_NOTICE, "Client updated.", struct_data={
			"client_id": client_id,
			"fields": " ".join(client_update.keys())
		})


	async def delete_client(self, client_id: str):
		client = await self.get_client(client_id)
		assert_client_is_editable(client)
		await self.StorageService.delete(self.ClientCollection, client_id)
		self._delete_from_cache(client_id)
		L.log(asab.LOG_NOTICE, "Client deleted.", struct_data={"client_id": client_id})


	async def validate_client_authorize_options(
		self,
		client: Client,
		redirect_uri: str,
		grant_type: str = None,
		response_type: str = None,
	):
		"""
		Verify that the specified authorization parameters are valid for the client.
		"""
		if not self.OIDCService.DisableRedirectUriValidation and not validate_redirect_uri(
			redirect_uri, client.redirect_uris, client.redirect_uri_validation_method):
			raise exceptions.InvalidRedirectURI(client_id=client.client_id, redirect_uri=redirect_uri)

		if grant_type is not None and grant_type not in client.grant_types:
			raise exceptions.ClientError(client_id=client.client_id, grant_type=grant_type)

		if response_type not in client.response_types:
			raise exceptions.ClientError(client_id=client.client_id, response_type=response_type)

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

		client_dict = await self.get_client(client_id)

		# Check if used authentication method matches the pre-configured one
		expected_auth_method = (
			client_dict.token_endpoint_auth_method or OAuth2.TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)
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


	def _normalize_client(self, client: dict):
		client = {**client}  # Do not modify the original client
		client["client_id"] = client["_id"]
		if client.get("managed_by"):
			client["read_only"] = True
		cookie_svc = self.App.get_service("seacatauth.CookieService")
		client["cookie_name"] = cookie_svc.get_cookie_name(client["_id"])
		if client.get("seacatauth_credentials") is True:
			credentials_service = self.App.get_service("seacatauth.CredentialsService")
			provider = credentials_service.CredentialProviders["client"]
			client["credentials_id"] = provider._format_credentials_id(client["_id"])
		return client


	def _deserialize_client(self, db_dict: dict) -> Client:
		"""
		Convert a database dict to a Client object
		"""
		# Known Client fields
		client_fields = {f.name for f in dataclasses.fields(Client)}
		kwargs = {}
		extra = {}
		for k, v in db_dict.items():
			if k in client_fields:
				kwargs[k] = v
			elif k == "__client_secret":
				kwargs["_client_secret"] = v
			else:
				extra[k] = v

		print("DEBUG extra", extra)
		kwargs["extra"] = extra

		# Add generated fields
		kwargs["client_id"] = db_dict["_id"]
		kwargs["client_id_issued_at"] = db_dict["_c"]
		cookie_svc = self.App.get_service("seacatauth.CookieService")
		kwargs["cookie_name"] = cookie_svc.get_cookie_name(db_dict["_id"])
		if db_dict.get("seacatauth_credentials") is True:
			credentials_service = self.App.get_service("seacatauth.CredentialsService")
			provider = credentials_service.CredentialProviders["client"]
			kwargs["credentials_id"] = provider._format_credentials_id(db_dict["_id"])

		# TEMPORARY
		kwargs["_raw"] = db_dict
		return Client(**kwargs)


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
	if client.get("read_only"):
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
