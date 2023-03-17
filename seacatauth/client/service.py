import datetime
import logging
import os.path
import re
import secrets
import urllib.parse

import asab.storage.exceptions
import asab.exceptions

from seacatauth.client import exceptions

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
	# "client_secret_basic",
	# "client_secret_post",
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
		"pattern": "^[-_a-zA-Z0-9]{8,64}$",
		"description": "(Non-canonical) Preferred client ID."},
	"client_name": {  # Can have language tags (e.g. "client_name#cs")
		"type": "string",
		"description": "Name of the Client to be presented to the End-User."},
	"client_uri": {  # Can have language tags
		"type": "string",
		"description": "URL of the home page of the Client."},
	"cookie_domain": {
		"type": "string",
		"pattern": "^[a-z0-9\\.-]{1,61}\\.[a-z]{2,}$|^$",
		"description":
			"Domain of the client cookie. Defaults to the application's global cookie domain."},
	"redirect_uris": {
		"type": "array",
		"description": "Array of Redirection URI values used by the Client."},
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


	async def initialize(self, app):
		self.OIDCService = app.get_service("seacatauth.OpenIdConnectService")


	def build_filter(self, match_string):
		return {"$or": [
			{"_id": re.compile("^{}".format(re.escape(match_string)))},
			{"client_name": re.compile(re.escape(match_string), re.IGNORECASE)},
		]}


	async def iterate(self, page: int = 0, limit: int = None, query_filter: str = None):
		collection = self.StorageService.Database[self.ClientCollection]

		if query_filter is None:
			query_filter = {}
		else:
			query_filter = self.build_filter(query_filter)
		cursor = collection.find(query_filter)

		cursor.sort("_c", -1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		async for client in cursor:
			if "__client_secret" in client:
				client.pop("__client_secret")
			yield client


	async def count(self, query_filter: dict = None):
		collection = self.StorageService.Database[self.ClientCollection]
		if query_filter is None:
			query_filter = {}
		else:
			query_filter = self.build_filter(query_filter)
		return await collection.count_documents(query_filter)


	async def get(self, client_id: str):
		client = await self.StorageService.get(self.ClientCollection, client_id, decrypt=["__client_secret"])
		if "__client_secret" in client:
			client["__client_secret"] = client["__client_secret"].decode("ascii")
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
		response_types = kwargs.get("response_types", frozenset(["code"]))
		for v in response_types:
			assert v in RESPONSE_TYPES

		grant_types = kwargs.get("grant_types", frozenset(["authorization_code"]))
		for v in grant_types:
			assert v in GRANT_TYPES

		application_type = kwargs.get("application_type", "web")
		assert application_type in APPLICATION_TYPES

		token_endpoint_auth_method = kwargs.get("token_endpoint_auth_method", "none")
		# TODO: The default should be "client_secret_basic". Change this once implemented.
		assert token_endpoint_auth_method in TOKEN_ENDPOINT_AUTH_METHODS

		if _custom_client_id is not None:
			client_id = _custom_client_id
			L.warning("Creating a client with custom ID", struct_data={"client_id": client_id})
		else:
			client_id = secrets.token_urlsafe(self.ClientIdLength)
		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id)

		if token_endpoint_auth_method == "none":
			# The client is PUBLIC
			# Clients incapable of maintaining the confidentiality of their
			# credentials (e.g., clients executing on the device used by the
			# resource owner, such as an installed native application or a web
			# browser-based application), and incapable of secure client
			# authentication via any other means.
			# The authorization server MAY establish a client authentication method
			# with public clients. However, the authorization server MUST NOT rely
			# on public client authentication for the purpose of identifying the
			# client.
			client_secret = None
			client_secret_expires_at = None
		elif token_endpoint_auth_method == "client_secret_basic":
			raise NotImplementedError("Token endpoint auth method 'client_secret_basic' is not supported.")
			# TODO: Finish implementing authorization with client secret
			# The client is CONFIDENTIAL
			# Clients capable of maintaining the confidentiality of their
			# credentials (e.g., client implemented on a secure server with
			# restricted access to the client credentials), or capable of secure
			# client authentication using other means.
			# Confidential clients are typically issued (or establish) a set of
			# client credentials used for authenticating with the authorization
			# server (e.g., password, public/private key pair).
			client_secret, client_secret_expires_at = self._generate_client_secret()
			upsertor.set("__client_secret", client_secret.encode("ascii"), encrypt=True)
			if client_secret_expires_at is not None:
				upsertor.set("client_secret_expires_at", client_secret_expires_at)
		else:
			# The client is CONFIDENTIAL
			# Valid method type, not implemented yet
			raise NotImplementedError("token_endpoint_auth_method = {!r}".format(token_endpoint_auth_method))

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

		# Optional client metadata
		for k in frozenset([
			"client_name", "client_uri", "logout_uri", "cookie_domain", "custom_data", "login_uri",
			"authorize_anonymous_users", "authorize_uri"]):
			v = kwargs.get(k)
			if v is not None and not (isinstance(v, str) and len(v) == 0):
				upsertor.set(k, v)

		try:
			await upsertor.execute(event_type=EventTypes.CLIENT_REGISTERED)
		except asab.storage.exceptions.DuplicateError:
			raise asab.exceptions.Conflict(key="client_id", value=client_id)

		L.log(asab.LOG_NOTICE, "Client created", struct_data={"client_id": client_id})

		response = {
			"client_id": client_id,
			"client_id_issued_at": int(datetime.datetime.now(datetime.timezone.utc).timestamp())}

		if client_secret is not None:
			response["client_secret"] = client_secret
			if client_secret_expires_at is not None:
				response["client_secret_expires_at"] = client_secret_expires_at

		return response


	async def reset_secret(self, client_id: str):
		client = await self.get(client_id)
		if client["token_endpoint_auth_method"] == "none":
			# The authorization server MAY establish a client authentication method with public clients.
			# However, the authorization server MUST NOT rely on public client authentication for the purpose
			# of identifying the client. [rfc6749#section-3.1.2]
			raise asab.exceptions.ValidationError("Cannot set secret for public client")
		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id, version=client["_v"])
		client_secret, client_secret_expires_at = self._generate_client_secret()
		upsertor.set("__client_secret", client_secret.encode("ascii"), encrypt=True)
		if client_secret_expires_at is not None:
			upsertor.set("client_secret_expires_at", client_secret_expires_at)
		await upsertor.execute(event_type=EventTypes.CLIENT_SECRET_RESET)
		L.log(asab.LOG_NOTICE, "Client secret updated", struct_data={"client_id": client_id})

		response = {"client_secret": client_secret}
		if client_secret_expires_at is not None:
			response["client_secret_expires_at"] = client_secret_expires_at

		return response


	async def update(self, client_id: str, **kwargs):
		client = await self.get(client_id)
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
				upsertor.set(k, v)

		await upsertor.execute(event_type=EventTypes.CLIENT_UPDATED)
		L.log(asab.LOG_NOTICE, "Client updated", struct_data={
			"client_id": client_id,
			"fields": " ".join(client_update.keys())})


	async def delete(self, client_id: str):
		await self.StorageService.delete(self.ClientCollection, client_id)
		L.log(asab.LOG_NOTICE, "Client deleted", struct_data={"client_id": client_id})


	async def authorize_client(
		self,
		client: dict,
		scope: list,
		redirect_uri: str,
		client_secret: str = None,
		grant_type: str = None,
		response_type: str = None,
	):
		if client_secret is None:
			# The client MAY omit the parameter if the client secret is an empty string.
			# [rfc6749#section-2.3.1]
			client_secret = ""
		if "client_secret_expires_at" in client \
			and client["client_secret_expires_at"] != 0 \
			and client["client_secret_expires_at"] < datetime.datetime.now(datetime.timezone.utc):
			raise exceptions.InvalidClientSecret(client["_id"])
		if client_secret != client.get("__client_secret", ""):
			raise exceptions.InvalidClientSecret(client["_id"])

		if not validate_redirect_uri(
			redirect_uri, client["redirect_uris"], client.get("redirect_uri_validation_method")):
			raise exceptions.InvalidRedirectURI(client_id=client["_id"], redirect_uri=redirect_uri)

		if grant_type is not None and grant_type not in client["grant_types"]:
			raise exceptions.ClientError(client_id=client["_id"], grant_type=grant_type)

		if response_type not in client["response_types"]:
			raise exceptions.ClientError(client_id=client["_id"], response_type=response_type)

		return True

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


def validate_redirect_uri(redirect_uri: str, registered_uris: list, validation_method: str = "full_match"):
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
