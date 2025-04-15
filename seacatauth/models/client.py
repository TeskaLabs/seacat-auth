import dataclasses
import logging
import base64
import datetime
import typing
import asab

from ..models.const import ResourceId
from .. import AuditLogger, generic
from ..authz.rbac.service import RBACService


L = logging.getLogger(__name__)


class Client:

	class OAuth2:
		def __init__(
			self,
			_id: str,
			client_name: str,
			client_uri: str,
			redirect_uris: list,
			application_type: str,
			response_types: list,
			grant_types: list,
			token_endpoint_auth_method: str,
			code_challenge_method: str,
			default_max_age: str,
			__client_secret: str,
			client_secret_expires_at: datetime.datetime,
			**kwargs
		):
			self.ClientId = _id
			self.ClientName = client_name
			self.ClientUri = client_uri
			self.RedirectUris = redirect_uris
			self.ApplicationType = application_type
			self.ResponseTypes = response_types
			self.GrantTypes = grant_types
			self.TokenEndpointAuthMethod = token_endpoint_auth_method
			self.CodeChallengeMethod = code_challenge_method
			self.DefaultMaxAge = default_max_age
			self._ClientSecretHash = __client_secret
			self.ClientSecretExpiresAt = client_secret_expires_at


		def is_confidential(self) -> bool:
			if self.TokenEndpointAuthMethod == "none":
				return False
			elif self.TokenEndpointAuthMethod in {"client_secret_basic", "client_secret_post"}:
				return True

			raise NotImplementedError(
				"Unsupported token_endpoint_auth_method: {!r}".format(self.TokenEndpointAuthMethod))


		def verify_secret(self, client_secret: str) -> bool:
			"""
			Verify client secret.

			Args:
				client_secret: Client secret to verify

			Returns:
				bool: If the client secret is valid
			"""
			if (
				self.ClientSecretExpiresAt is not None
				and self.ClientSecretExpiresAt < datetime.datetime.now(datetime.timezone.utc)
			):
				L.log(asab.LOG_NOTICE, "Client secret expired.", client_id=self.ClientId)
				return False

			if not generic.argon2_verify(self._ClientSecretHash, client_secret):
				return False

			return True


		def verify_code_challenge_method(self, code_challenge_method: str) -> bool:
			"""
			Verify code challenge method.

			Args:
				code_challenge_method: Code challenge method to verify

			Returns:
				bool: If the code challenge method is valid
			"""
			if code_challenge_method not in {"none", "plain", "s256"}:
				return False

			if self.CodeChallengeMethod != code_challenge_method:
				return False

			return True


	def __init__(self, client_dict):
		self._Dict: dict = client_dict
		self.Id: str = self._Dict["_id"]
		self.Version: int = self._Dict["_v"]
		self.CreatedAt: datetime.datetime = self._Dict["_c"]
		self.ModifiedAt: datetime.datetime = self._Dict["_m"]

		# OpenID Connect attributes
		self.ClientName: str = self._Dict.get("client_name")
		self.ClientUri: str = self._Dict.get("client_uri")
		self.RedirectUris: list = self._Dict.get("redirect_uris")
		self.ApplicationType: str = self._Dict.get("application_type")
		self.ResponseTypes: list = self._Dict.get("response_types")
		self.GrantTypes: list = self._Dict.get("grant_types")
		self.TokenEndpointAuthMethod: str = self._Dict.get("token_endpoint_auth_method")
		self.CodeChallengeMethod: str = self._Dict.get("code_challenge_method")
		self.DefaultMaxAge: str = self._Dict.get("default_max_age")
		self._ClientSecretHash: str = self._Dict.get("__client_secret")
		self.ClientSecretExpiresAt: datetime.datetime = self._Dict.get("client_secret_expires_at")

		# SeaCat Auth attributes
		self.RedirectUriValidationMethod: str = self._Dict.get("redirect_uri_validation_method")
		self.CookieDomain: str = self._Dict.get("cookie_domain")
		self.CookieWebhookUri: str = self._Dict.get("cookie_webhook_uri")
		self.CookieEntryUri: str = self._Dict.get("cookie_entry_uri")
		self.AuthorizeUri: str = self._Dict.get("authorize_uri")
		self.LoginUri: str = self._Dict.get("login_uri")
		self.AuthorizeAnonymousUsers: bool = self._Dict.get("authorize_anonymous_users")
		self.AnonymousCid: str = self._Dict.get("anonymous_cid")
		self.SessionExpiration: float = self._Dict.get("session_expiration")


	def __repr__(self):
		return ("<{} Client {!r} ({})>".format(
			"Confidential" if self.is_confidential() else "Public",
			self.Id,
			self.ClientName,
		))


	def serialize(self) -> dict:
		client_dict = {
			"_id": self.Id,
			"_v": self.Version,
			"_c": self.CreatedAt,
			"_m": self.ModifiedAt,
			"client_id": self.Id,
			"label": self.ClientName or self.Id,
		}
		return client_dict







def _get_credentials_from_authorization_header(request) -> typing.Tuple[typing.Optional[str], typing.Optional[str]]:
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


async def _get_credentials_from_post_data(request) -> typing.Tuple[typing.Optional[str], typing.Optional[str]]:
	post_data = await request.post()
	return post_data.get("client_id"), post_data.get("client_secret")
