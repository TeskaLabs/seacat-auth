import base64
import binascii
import datetime
import logging
import re
import secrets
import typing
import urllib.parse

import asab.storage.exceptions
import asab.exceptions
import pymongo
from asab.utils import convert_to_seconds

from .. import exceptions
from .. import generic
from ..events import EventTypes

#

L = logging.getLogger(__name__)

#

# https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
# TODO: Supported OAuth/OIDC param values should be managed by the OpenIdConnect module, not Client.
GRANT_TYPES = [
	"authorization_code",
	# "implicit",
	# "refresh_token"
]
RESPONSE_TYPES = [
	"code",
	# "id_token",
	# "token"
]
APPLICATION_TYPES = [
	"web",
	# "native"
]
TOKEN_ENDPOINT_AUTH_METHODS = [
	"none",
	"client_secret_basic",
	"client_secret_post",
	# "client_secret_jwt",
	# "private_key_jwt"
]
REDIRECT_URI_VALIDATION_METHODS = [
	"full_match",
	"prefix_match",
	"none",
]
CLIENT_METADATA_SCHEMA = {
	# The order of the properties is preserved in the UI form
	"preferred_client_id": {
		"type": "string",
		"pattern": "^[-_a-zA-Z0-9]{4,64}$",
		"description": "(Non-canonical) Preferred client ID."},
	"client_name": {  # Can have language tags (e.g. "client_name#cs")
		"type": "string",
		"description": "Name of the Client to be presented to the End-User."},
	"client_uri": {  # Can have language tags
		"type": "string",
		"description": "URL of the home page of the Client."},
	"cookie_domain": {  # NON-CANONICAL
		"type": "string",
		"pattern": "^[a-z0-9\\.-]{1,61}\\.[a-z]{2,}$|^$",
		"description":
			"Domain of the client cookie. Defaults to the application's global cookie domain."},
	"cookie_webhook_uri": {  # NON-CANONICAL
		"type": "string",
		"description":
			"Webhook URI for setting additional custom cookies at the cookie entrypoint. "
			"It must be a back-channel URI and it must accept a JSON PUT request and "
			"respond with a JSON object of cookies to set."},
	"cookie_entry_uri": {  # NON-CANONICAL
		"type": "string",
		"description":
			"Public URI of the client's cookie entrypoint."},
	"redirect_uris": {
		"type": "array",
		"description": "Array of Redirection URI values used by the Client.",
		"items": {"type": "string"}},
	#  "contacts": {},
	# "custom_data": {  # NON-CANONICAL
	# 	"type": "object", "description": "(Non-canonical) Additional client data."},
	# "logout_uri": {  # NON-CANONICAL
	# 	"type": "string", "description": "(Non-canonical) URI that will be called on session logout."},
	"application_type": {
		"type": "string",
		"description": "Kind of the application. The default, if omitted, is `web`.",
		"enum": APPLICATION_TYPES},
	"response_types": {
		"type": "array",
		"description":
			"JSON array containing a list of the OAuth 2.0 response_type values "
			"that the Client is declaring that it will restrict itself to using. "
			"If omitted, the default is that the Client will use only the `code` Response Type.",
		"items": {
			"type": "string",
			"enum": RESPONSE_TYPES}},
	"grant_types": {
		"type": "array",
		"description":
			"JSON array containing a list of the OAuth 2.0 Grant Types "
			"that the Client is declaring that it will restrict itself to using. "
			"If omitted, the default is that the Client will use only the `authorization_code` Grant Type.",
		"items": {
			"type": "string",
			"enum": GRANT_TYPES}},
	# "logo_uri": {},  # Can have language tags
	# "policy_uri": {},  # Can have language tags
	# "tos_uri": {},  # Can have language tags
	# "jwks_uri": {},
	# "jwks": {},
	# "sector_identifier_uri": {},
	# "subject_type": {},
	# "id_token_signed_response_alg": {},
	# "id_token_encrypted_response_alg": {},
	# "id_token_encrypted_response_enc": {},
	# "userinfo_signed_response_alg": {},
	# "userinfo_encrypted_response_alg": {},
	# "userinfo_encrypted_response_enc": {},
	# "request_object_signing_alg": {},
	# "request_object_encryption_alg": {},
	# "request_object_encryption_enc": {},
	"token_endpoint_auth_method": {
		"type": "string",
		"description":
			"Requested Client Authentication method for the Token Endpoint. "
			"If omitted, the default is `none`.",
		"enum": TOKEN_ENDPOINT_AUTH_METHODS},
	# "token_endpoint_auth_signing_alg": {},
	# "default_max_age": {},
	# "require_auth_time": {},
	# "default_acr_values": {},
	# "initiate_login_uri": {},
	# "request_uris": {},
	"code_challenge_method": {
		"type": "string",
		"description":
			"Code Challenge Method (PKCE) that the Client will be required to use at the Authorize Endpoint. "
			"The default, if omitted, is `none`.",
		"enum": ["none", "plain", "S256"]},
	"authorize_uri": {  # NON-CANONICAL
		"type": "string",
		"description":
			"URL of OAuth authorize endpoint. Useful when logging in from different than the default domain."},
	"login_uri": {  # NON-CANONICAL
		"type": "string",
		"description": "URL of preferred login page."},
	"authorize_anonymous_users": {  # NON-CANONICAL
		"type": "boolean",
		"description": "Allow authorize requests with anonymous users."},
	"anonymous_cid": {  # NON-CANONICAL
		"type": "string",
		"description": "ID of credentials that is used for authenticating anonymous sessions."},
	"session_expiration": {  # NON-CANONICAL
		"oneOf": [{"type": "string"}, {"type": "number"}],
		"description":
			"Client session expiration. The value can be either the number of seconds "
			"or a time-unit string such as '4 h' or '3 d'."},
	"redirect_uri_validation_method": {  # NON-CANONICAL
		"type": "string",
		"description":
			"Specifies the method how the redirect URI used in authorization requests is validated. "
			"The default value is 'full_match', in which the requested redirect URI must fully match "
			"one of the registered URIs.",
		"enum": REDIRECT_URI_VALIDATION_METHODS},
}

REGISTER_CLIENT_SCHEMA = {
	"type": "object",
	"required": ["redirect_uris", "client_name"],
	"additionalProperties": False,
	"properties": CLIENT_METADATA_SCHEMA,
	# "patternProperties": {
	#   # Language-specific metadata with RFC 5646 language tags
	# 	"^client_name#[-a-zA-Z0-9]+$": {"type": "string"},
	# 	"^logo_uri#[-a-zA-Z0-9]+$": {"type": "string"},
	# 	"^client_uri#[-a-zA-Z0-9]+$": {"type": "string"},
	# 	"^policy_uri#[-a-zA-Z0-9]+$": {"type": "string"},
	# 	"^tos_uri#[-a-zA-Z0-9]+$": {"type": "string"},
	# }
}

UPDATE_CLIENT_SCHEMA = {
	"type": "object",
	"additionalProperties": False,
	"properties": CLIENT_METADATA_SCHEMA
}

# TODO: Configurable templates
CLIENT_TEMPLATES = {
	"Public web application": {
		"application_type": "web",
		"token_endpoint_auth_method": "none",
		"grant_types": ["authorization_code"],
		"response_types": ["code"]},
	# "Public mobile application": {
	# 	"application_type": "native",
	# 	"token_endpoint_auth_method": "none",
	# 	"grant_types": ["authorization_code"],
	# 	"response_types": ["code"]},
	"Custom": {},
}


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
			CLIENT_METADATA_SCHEMA.pop("preferred_client_id")

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


	def build_filter(self, match_string):
		return {"$or": [
			{"_id": re.compile("^{}".format(re.escape(match_string)))},
			{"client_name": re.compile(re.escape(match_string), re.IGNORECASE)},
		]}


	async def iterate(
		self,
		page: int = 0,
		limit: int = None,
		query_filter: str = None,
		sort_by: typing.Optional[typing.List[tuple]] = None
	):
		collection = self.StorageService.Database[self.ClientCollection]

		if query_filter is None:
			query_filter = {}
		else:
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
			if "__client_secret" in client:
				client.pop("__client_secret")
			yield self._normalize_client(client)


	async def count(self, query_filter: dict = None):
		collection = self.StorageService.Database[self.ClientCollection]
		if query_filter is None:
			query_filter = {}
		else:
			query_filter = self.build_filter(query_filter)
		return await collection.count_documents(query_filter)


	async def get(self, client_id: str):
		"""
		Get client metadata

		@param client_id:
		@return:
		"""
		# Try to get client from cache
		client = self._get_from_cache(client_id)
		if client:
			return client

		# Get from the database
		client = await self.StorageService.get(self.ClientCollection, client_id)
		client = self._normalize_client(client)

		self._store_in_cache(client_id, client)

		return client


	async def register(
		self, *,
		redirect_uris: list,
		_custom_client_id: str = None,
		**kwargs
	):
		"""
		Register a new OpenID Connect client
		https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration

		:param redirect_uris: Array of Redirection URI values used by the Client.
		:type redirect_uris: list
		:param _custom_client_id: NON-CANONICAL. Request a specific ID for the client.
		:type _custom_client_id: str
		:return: Dict containing the issued client_id and client_secret.
		"""
		response_types = kwargs.get("response_types", {"code"})
		for v in response_types:
			assert v in RESPONSE_TYPES

		grant_types = kwargs.get("grant_types", {"authorization_code"})
		for v in grant_types:
			assert v in GRANT_TYPES

		application_type = kwargs.get("application_type", "web")
		assert application_type in APPLICATION_TYPES

		if _custom_client_id is not None:
			client_id = _custom_client_id
			L.warning("Creating a client with custom ID.", struct_data={"client_id": client_id})
		else:
			client_id = secrets.token_urlsafe(self.ClientIdLength)
		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id)

		# TODO: The default should be "client_secret_basic".
		token_endpoint_auth_method = kwargs.get("token_endpoint_auth_method", "none")
		assert token_endpoint_auth_method in TOKEN_ENDPOINT_AUTH_METHODS
		upsertor.set("token_endpoint_auth_method", token_endpoint_auth_method)

		self._check_redirect_uris(redirect_uris, application_type, grant_types)
		upsertor.set("redirect_uris", list(redirect_uris))

		self._check_grant_types(grant_types, response_types)
		upsertor.set("grant_types", list(grant_types))
		upsertor.set("response_types", list(response_types))

		upsertor.set("application_type", application_type)

		# Register allowed PKCE Code Challenge Methods
		code_challenge_method = kwargs.get("code_challenge_method", "none")
		self.OIDCService.PKCE.validate_code_challenge_method_registration(code_challenge_method)
		upsertor.set("code_challenge_method", code_challenge_method)

		redirect_uri_validation_method = kwargs.get("redirect_uri_validation_method", "full_match")
		assert redirect_uri_validation_method in REDIRECT_URI_VALIDATION_METHODS
		upsertor.set("redirect_uri_validation_method", redirect_uri_validation_method)

		session_expiration = kwargs.get("session_expiration")
		if session_expiration is not None:
			if isinstance(convert_to_seconds, str):
				session_expiration = convert_to_seconds(convert_to_seconds)
			upsertor.set("session_expiration", session_expiration)

		# Optional client metadata
		for k in {
			"client_name", "client_uri", "logout_uri", "cookie_domain", "custom_data", "login_uri",
			"authorize_anonymous_users", "authorize_uri", "cookie_webhook_uri", "cookie_entry_uri",
			"anonymous_cid"
		}:
			v = kwargs.get(k)
			if v is not None and not (isinstance(v, str) and len(v) == 0):
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
		client = await self.get(client_id)
		self.assert_client_is_editable(client)
		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id, version=client["_v"])
		client_secret, client_secret_expires_at = self._generate_client_secret()
		client_secret_hash = generic.argon2_hash(client_secret)
		upsertor.set("__client_secret", client_secret_hash)
		if client_secret_expires_at is not None:
			upsertor.set("client_secret_expires_at", client_secret_expires_at)

		await upsertor.execute(event_type=EventTypes.CLIENT_SECRET_RESET)
		self._delete_from_cache(client_id)
		L.log(asab.LOG_NOTICE, "Client secret updated.", struct_data={"client_id": client_id})

		return client_secret, client_secret_expires_at


	async def update(self, client_id: str, **kwargs):
		client = await self.get(client_id)
		self.assert_client_is_editable(client)
		client_update = {}
		for k, v in kwargs.items():
			if k not in CLIENT_METADATA_SCHEMA:
				raise asab.exceptions.ValidationError("Unexpected argument: {}".format(k))
			client_update[k] = v

		self._check_redirect_uris(
			redirect_uris=client_update.get("redirect_uris", client["redirect_uris"]),
			application_type=client_update.get("application_type", client["application_type"]),
			grant_types=client_update.get("grant_types", client["grant_types"]),
			client_uri=client_update.get("client_uri", client.get("client_uri")))

		self._check_grant_types(
			grant_types=client_update.get("grant_types", client["grant_types"]),
			response_types=client_update.get("response_types", client["response_types"]))

		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id, version=client["_v"])

		# Register allowed PKCE Code Challenge Methods
		if "code_challenge_method" in kwargs:
			self.OIDCService.PKCE.validate_code_challenge_method_registration(kwargs["code_challenge_method"])

		for k, v in client_update.items():
			if v is None or (isinstance(v, str) and len(v) == 0):
				upsertor.unset(k)
			else:
				if k == "session_expiration" and isinstance(v, str):
					try:
						v = convert_to_seconds(v)
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


	async def delete(self, client_id: str):
		client = await self.get(client_id)
		self.assert_client_is_editable(client)
		await self.StorageService.delete(self.ClientCollection, client_id)
		self._delete_from_cache(client_id)
		L.log(asab.LOG_NOTICE, "Client deleted.", struct_data={"client_id": client_id})


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


	async def authenticate_client_request(
		self,
		request,
		expected_client_id: typing.Optional[str] = None
	) -> typing.Optional[str]:
		"""
		Verify client ID and secret.
		"""
		if expected_client_id:
			# Client ID is known - Use the pre-configured authentication method
			client_dict = await self.get(expected_client_id)
			expected_auth_method = client_dict.get("token_endpoint_auth_method", "client_secret_basic")
			if expected_auth_method == "none":
				return expected_client_id
			if expected_auth_method == "client_secret_basic":
				client_id, client_secret = self._get_credentials_from_authorization_header(request)
			elif expected_auth_method == "client_secret_post":
				client_id, client_secret = await self._get_credentials_from_post_data(request)
			else:
				raise NotImplementedError("Unsupported client authentication method: {}".format(expected_auth_method))

			if not client_id:
				raise exceptions.ClientAuthenticationError(
					"Failed to get client credentials from request.",
					client_id=expected_client_id,
				)
			elif client_id != expected_client_id:
				raise exceptions.ClientAuthenticationError(
					"Client IDs do not match (expected {!r}).".format(expected_client_id),
					client_id=client_id,
				)

		else:
			# Client ID is not known in advance - Try to extract it from the request
			client_id, client_secret = self._get_credentials_from_authorization_header(request)
			if client_id and client_secret:
				auth_method = "client_secret_basic"
			else:
				client_id, client_secret = await self._get_credentials_from_post_data(request)
				if client_id and client_secret:
					auth_method = "client_secret_post"
				else:
					# Public client - Authentication not required
					# auth_method = "none"
					return None

			assert client_id
			client_dict = await self.get(client_id)
			expected_auth_method = client_dict.get("token_endpoint_auth_method", "client_secret_basic")
			if auth_method != expected_auth_method:
				raise exceptions.ClientAuthenticationError(
					"Unexpected authentication method (expected {!r}, {!r}).".format(
						expected_auth_method, auth_method),
					client_id=client_id,
				)
			elif auth_method == "none":
				# Public client - no secret verification required
				return client_id

		# Check secret expiration
		client_secret_expires_at = client_dict.get("client_secret_expires_at", None)
		if client_secret_expires_at and client_secret_expires_at < datetime.datetime.now(datetime.timezone.utc):
			raise exceptions.ClientAuthenticationError("Expired client secret.", client_id=expected_client_id)

		# Verify client secret
		client_secret_hash = client_dict.get("__client_secret", None)
		if not generic.argon2_verify(client_secret_hash, client_secret):
			raise exceptions.ClientAuthenticationError("Incorrect client secret.", client_id=client_id)

		return client_id


	def assert_client_is_editable(self, client: dict):
		if client.get("read_only"):
			raise exceptions.NotEditableError("Client is not editable.")
		return True


	def _get_credentials_from_authorization_header(
		self, request
	) -> typing.Tuple[typing.Optional[str], typing.Optional[str]]:
		auth_header = request.headers.get("Authorization")
		if not auth_header:
			return None, None
		try:
			token_type, auth_token = auth_header.split(" ")
		except ValueError:
			return None, None
		if token_type != "Basic":
			return None, None
		try:
			auth_token_decoded = base64.urlsafe_b64decode(auth_token.encode("ascii")).decode("ascii")
		except (binascii.Error, UnicodeDecodeError):
			return None, None
		try:
			client_id, client_secret = auth_token_decoded.split(":")
		except ValueError:
			return None, None
		return client_id, client_secret


	async def _get_credentials_from_post_data(
		self, request
	) -> typing.Tuple[typing.Optional[str], typing.Optional[str]]:
		post_data = await request.post()
		if not ("client_id" in post_data and "client_secret" in post_data):
			return None, None
		return post_data["client_id"], post_data["client_secret"]


	def _check_grant_types(self, grant_types, response_types):
		# https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
		# The following table lists the correspondence between response_type values that the Client will use
		# and grant_type values that MUST be included in the registered grant_types list:
		# 	code: authorization_code
		# 	id_token: implicit
		# 	token id_token: implicit
		# 	code id_token: authorization_code, implicit
		# 	code token: authorization_code, implicit
		# 	code token id_token: authorization_code, implicit
		if "code" in response_types and "authorization_code" not in grant_types:
			raise asab.exceptions.ValidationError(
				"Response type 'code' requires 'authorization_code' to be included in grant types")
		if "id_token" in response_types and "implicit" not in grant_types:
			raise asab.exceptions.ValidationError(
				"Response type 'id_token' requires 'implicit' to be included in grant types")
		if "token" in response_types and "implicit" not in grant_types:
			raise asab.exceptions.ValidationError(
				"Response type 'token' requires 'implicit' to be included in grant types")


	def _check_redirect_uris(
		self, redirect_uris: list, application_type: str, grant_types: list, client_uri: str = None):
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
		client["client_id"] = client["_id"]
		if client.get("managed_by"):
			client["read_only"] = True
		cookie_svc = self.App.get_service("seacatauth.CookieService")
		client["cookie_name"] = cookie_svc.get_cookie_name(client["_id"])
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
	token_endpoint_auth_method = client.get("token_endpoint_auth_method", "none")
	if token_endpoint_auth_method == "none":
		return False
	elif token_endpoint_auth_method in {"client_secret_basic", "client_secret_post"}:
		return True
	else:
		raise NotImplementedError("Unsupported token_endpoint_auth_method: {!r}".format(token_endpoint_auth_method))
