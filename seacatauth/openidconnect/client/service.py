import datetime
import logging
import re
import secrets
import urllib.parse

import asab.storage.exceptions
import asab.exceptions

from .. import exceptions

#

L = logging.getLogger(__name__)

#

# TODO: Implement support for remaining metadata
# https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
OIDC_GRANT_TYPES = ["authorization_code", "implicit", "refresh_token"]
OIDC_RESPONSE_TYPES = ["code", "id_token", "token"]
OIDC_APPLICATION_TYPES = ["web", "native"]
OIDC_TOKEN_ENDPOINT_AUTH_METHODS = [
	"none", "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"]
OIDC_CLIENT_METADATA_SCHEMA = {
	"type": "object",
	"required": ["redirect_uris"],
	"properties": {
		"redirect_uris": {
			"type": "array", "description": "Array of Redirection URI values used by the Client."},
		"client_name": {  # Can have language tags (e.g. "client_name#cs")
			"type": "string"},
		#  "contacts": {},
		"application_type": {
			"type": "string",
			"enum": OIDC_APPLICATION_TYPES},
		"response_types": {
			"type": "array",
			"items": {
				"type": "string",
				"enum": OIDC_RESPONSE_TYPES}},
		"grant_types": {
			"type": "array",
			"items": {
				"type": "string",
				"enum": OIDC_GRANT_TYPES}},
		# "logo_uri": {},  # Can have language tags
		"client_uri": {  # Can have language tags
			"type": "string"},
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
			"enum": OIDC_TOKEN_ENDPOINT_AUTH_METHODS},
		# "token_endpoint_auth_signing_alg": {},
		# "default_max_age": {},
		# "require_auth_time": {},
		# "default_acr_values": {},
		# "initiate_login_uri": {},
		# "request_uris": {},
		"custom_data": {  # NON-CANONICAL
			"type": "object", "description": "Additional client data."},
		"logout_uri": {  # NON-CANONICAL
			"type": "string", "description": "URI that will be called on session logout."},
	}
}


class ClientService(asab.Service):
	ClientCollection = "cl"
	ClientIdPattern = r"[a-z][a-z0-9._-]{2,31}"
	ClientSecretLength = 32
	ClientIdLength = 16

	def __init__(self, app, service_name="seacatauth.ClientService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.ClientIdRegex = re.compile("^{}$".format(self.ClientIdPattern))


	async def _initialize_webui_client(self, redirect_uris):
		await self.register(redirect_uris=redirect_uris, custom_data={"app_id": "seacat-webui"})


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


	async def get(self, client_id: str, include: list = frozenset()):
		client = await self.StorageService.get(self.ClientCollection, client_id)
		client = self.normalize_client(client, include)
		# TODO: Generate authorize URIs for the client (for convenience)
		return client


	def normalize_client(self, data, include):
		"""
		Remove confidential client data
		"""
		client = {
			k: v
			for k, v in data.items()
			if not k.startswith("__") or k in include
		}
		if "__client_secret" in client:
			client["__client_secret"] = client["__client_secret"].decode("ascii")
		return client


	async def register(
		self, redirect_uris: list, *,
		response_types: list = frozenset(["code"]),
		grant_types: list = frozenset(["authorization_code"]),
		application_type: str = "web",
		client_name: str = None,
		client_uri: str = None,
		token_endpoint_auth_method: str = "client_secret_basic",
		logout_uri: str = None,
		custom_data: dict = None,
		**kwargs
	):
		"""
		Register a new OpenID Connect client
		https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration

		:param redirect_uris: Array of Redirection URI values used by the Client.
		:type redirect_uris: list
		:param response_types: Array containing the OAuth 2.0 response_type values that the Client is declaring
			that it will restrict itself to using.
		:type response_types: list
		:param grant_types: Array containing the OAuth 2.0 Grant Types that the Client is declaring that it will
			restrict itself to using.
		:type grant_types: list
		:param application_type: Kind of the application. The defined values are "native" or "web".
		:type application_type: str
		:param client_name: Name of the Client to be presented to the End-User.
		:type client_name: str
		:param client_uri: URL of the home page of the Client.
		:type client_uri: str
		:param token_endpoint_auth_method: Requested Client Authentication method for the Token Endpoint.
		:type token_endpoint_auth_method: str
		:param logout_uri: NON-CANONICAL. URI that will be called on session logout.
		:type logout_uri: str
		:param custom_data: NON-CANONICAL. Additional client data.
		:type custom_data: str
		:return: Response containing the issued client_id and client_secret.
		"""
		for v in response_types:
			assert v in OIDC_RESPONSE_TYPES
		for v in grant_types:
			assert v in OIDC_GRANT_TYPES
		assert application_type in OIDC_APPLICATION_TYPES
		assert token_endpoint_auth_method in OIDC_TOKEN_ENDPOINT_AUTH_METHODS

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
		elif token_endpoint_auth_method == "client_secret_basic":
			# The client is CONFIDENTIAL
			# Clients capable of maintaining the confidentiality of their
			# credentials (e.g., client implemented on a secure server with
			# restricted access to the client credentials), or capable of secure
			# client authentication using other means.
			# Confidential clients are typically issued (or establish) a set of
			# client credentials used for authenticating with the authorization
			# server (e.g., password, public/private key pair).
			client_secret = secrets.token_urlsafe(self.ClientSecretLength)
			upsertor.set("__client_secret", client_secret.encode("ascii"), encrypt=True)
		else:
			# The client is CONFIDENTIAL
			# Valid method type, not implemented yet
			raise NotImplementedError("token_endpoint_auth_method = {!r}".format(token_endpoint_auth_method))

		upsertor.set("token_endpoint_auth_method", token_endpoint_auth_method)

		self._check_redirect_uris(redirect_uris, application_type, client_uri)
		upsertor.set("redirect_uris", list(redirect_uris))

		self._check_grant_types(grant_types, response_types)
		upsertor.set("grant_types", list(grant_types))
		upsertor.set("response_types", list(response_types))

		# Optional client metadata

		if client_name is not None:
			upsertor.set("client_name", client_name)

		if client_uri is not None:
			upsertor.set("client_uri", client_uri)

		if logout_uri is not None:
			upsertor.set("logout_uri", logout_uri)

		await upsertor.execute()
		L.log(asab.LOG_NOTICE, "OIDC client ID created", struct_data={
			"client_id": client_id,
			"client_name": client_name})

		response = {
			"client_id": client_id,
			"client_id_issued_at": int(datetime.datetime.now(datetime.timezone.utc).timestamp())}

		if client_secret is not None:
			response.update({
				"client_secret": client_secret,
				"client_secret_expires_at": client_secret})

		if custom_data is not None:
			upsertor.set("custom_data", custom_data)

		return response


	async def reset_secret(self, client_id: str):
		client = await self.get(client_id)
		if client["token_endpoint_auth_method"] == "none":
			# The authorization server MAY establish a client authentication method with public clients.
			# However, the authorization server MUST NOT rely on public client authentication for the purpose
			# of identifying the client. [rfc6749#section-3.1.2]
			raise asab.exceptions.ValidationError("Cannot set secret for public OIDC client")
		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id)
		client_secret = secrets.token_urlsafe(self.ClientSecretLength)
		upsertor.set("__client_secret", client_secret.encode("ascii"), encrypt=True)
		return client_secret


	async def update(
		self,
		client_id: str,
		**kwargs
	):
		client = await self.get(client_id)
		client_update = {}
		for k, v in kwargs.items():
			if k not in OIDC_CLIENT_METADATA_SCHEMA["properties"]:
				raise asab.exceptions.ValidationError("Unexpected argument: {}".format(k))
			client_update[k] = v

		self._check_redirect_uris(
			redirect_uris=client_update.get("redirect_uris", client["redirect_uris"]),
			application_type=client_update.get("application_type", client["application_type"]),
			client_uri=client_update.get("client_uri", client["client_uri"]))

		self._check_grant_types(
			grant_types=client_update.get("grant_types", client["grant_types"]),
			response_types=client_update.get("response_types", client["response_types"]))

		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id)

		for k, v in client_update.items():
			upsertor.set(k, v)

		await upsertor.execute()
		L.log(asab.LOG_NOTICE, "OIDC client updated", struct_data={"client_id": client_id})


	async def delete(self, client_id: str):
		self.StorageService.delete(self.ClientCollection, client_id)
		L.log(asab.LOG_NOTICE, "OIDC client deleted", struct_data={"client_id": client_id})


	async def authorize_client(
		self,
		client_id: str,
		scope: list,
		redirect_uri: str,
		client_secret: str = None,
		grant_type: str = None,
		response_type: str = None,
	):
		registered_client = await self.get(client_id, include=frozenset(["__client_secret"]))

		if client_secret is None:
			# The client MAY omit the parameter if the client secret is an empty string.
			# [rfc6749#section-2.3.1]
			client_secret = ""
		if redirect_uri not in registered_client["redirect_uris"]:
			raise exceptions.OpenIDConnectClientError(client_id=client_id, redirect_uri=redirect_uri)
		if grant_type not in registered_client["grant_types"]:
			raise exceptions.OpenIDConnectClientError(client_id=client_id, grant_type=grant_type)
		if response_type not in registered_client["response_types"]:
			raise exceptions.OpenIDConnectClientError(client_id=client_id, response_type=response_type)
		if client_secret != registered_client.get("__client_secret", ""):
			raise exceptions.OpenIDConnectClientError(client_id=client_id, client_secret=client_secret)

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


	def _check_redirect_uris(self, redirect_uris: list, application_type: str, client_uri: str = None):
		# https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
		# The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3.
		# The endpoint URI MUST NOT include a fragment component. [rfc6749#section-3.1.2]
		for uri in redirect_uris:
			parsed = urllib.parse.urlparse(uri)
			if len(parsed.netloc) == 0 or len(parsed.scheme) == 0 or len(parsed.fragment) == 0:
				raise asab.exceptions.ValidationError(
					"Redirect URI must be an absolute URI without a fragment component.")

			if application_type == "web":
				if parsed.scheme != "https://":
					raise asab.exceptions.ValidationError(
						"Web Clients using the OAuth Implicit Grant Type MUST only register URLs "
						"using the https scheme as redirect_uris.")
				if parsed.hostname == "localhost":
					raise asab.exceptions.ValidationError(
						"Web Clients using the OAuth Implicit Grant Type MUST NOT use localhost as the hostname.")
			elif application_type == "native":
				# TODO: Authorization Servers MAY place additional constraints on Native Clients.
				if parsed.scheme == "http://":
					if parsed.hostname == "localhost":
						# This is valid
						pass
					else:
						# Authorization Servers MAY reject Redirection URI values using the http scheme,
						# other than the localhost case for Native Clients.
						raise asab.exceptions.ValidationError(
							"Native Clients MUST only register redirect_uris using custom URI schemes "
							"or URLs using the http: scheme with localhost as the hostname.")
				else:
					# TODO: Support custom URI schemes
					raise asab.exceptions.ValidationError(
						"Native Clients MUST only register redirect_uris using custom URI schemes "
						"or URLs using the http: scheme with localhost as the hostname.")
