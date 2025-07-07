import logging
import datetime
import typing

from ..models.const import OAuth2


L = logging.getLogger(__name__)


class Client:

	def __init__(self, client_dict: dict):
		self._Dict: dict = client_dict
		self.Id: str = self._Dict["_id"]
		self.Version: int = self._Dict["_v"]
		self.CreatedAt: datetime.datetime = self._Dict["_c"]
		self.ModifiedAt: datetime.datetime = self._Dict["_m"]

		self.Label: str = self._Dict.get("client_name", self.Id)
		self.SeacatAuthCredentialsEnabled: bool = self._Dict["seacatauth_credentials"]
		self.SeacatAuthCredentialsId: typing.Optional[str] = self._Dict["seacatauth_credentials_id"]

		self.OAuth2: typing.Optional[_OAuth2] = _OAuth2.deserialize(self._Dict)


	def __repr__(self):
		return ("<Client {!r} (OAuth: {})>".format(
			self.Id,
			self.OAuth2 is not None,
		))


	def __getitem___(self, key: str):
		return self._Dict[key]


	def rest_get(self) -> dict:
		client_dict = {
			"_id": self.Id,
			"_v": self.Version,
			"_c": self.CreatedAt,
			"_m": self.ModifiedAt,
			"label": self.Label,
		}
		if self.OAuth2 is not None:
			client_dict["oauth"] = self.OAuth2.rest_get()
		return client_dict


class _OAuth2:
	def __init__(self, client_dict: dict):
		# OAuth 2.0 / OpenID Connect attributes
		self.ClientId: str = client_dict.get("client_id")
		self.ClientName: str = client_dict.get("client_name")
		self.ClientUri: str = client_dict.get("client_uri")
		self.RedirectUris: list = client_dict.get("redirect_uris")
		self.ApplicationType: str = client_dict.get("application_type")
		self.ResponseTypes: list = client_dict.get("response_types")
		self.GrantTypes: list = client_dict.get("grant_types")
		self.TokenEndpointAuthMethod: str = client_dict.get("token_endpoint_auth_method")
		self.CodeChallengeMethod: str = client_dict.get("code_challenge_method")
		self.DefaultMaxAge: str = client_dict.get("default_max_age")
		self._ClientSecretHash: str = client_dict.get("__client_secret")
		self.ClientSecretExpiresAt: datetime.datetime = client_dict.get("client_secret_expires_at")

		# SeaCat Auth attributes
		self.RedirectUriValidationMethod: str = client_dict.get("redirect_uri_validation_method")
		self.CookieDomain: str = client_dict.get("cookie_domain")
		self.CookieWebhookUri: str = client_dict.get("cookie_webhook_uri")
		self.CookieEntryUri: str = client_dict.get("cookie_entry_uri")
		self.AuthorizeUri: str = client_dict.get("authorize_uri")
		self.LoginUri: str = client_dict.get("login_uri")
		self.AuthorizeAnonymousUsers: bool = client_dict.get("authorize_anonymous_users")
		self.AnonymousCid: str = client_dict.get("anonymous_cid")
		self.SessionExpiration: float = client_dict.get("session_expiration")


	@classmethod
	def deserialize(cls, client_dict: dict):
		"""
		Deserializes a client dictionary into an _OAuth2 instance.
		If the dictionary does not contain the mandatory OAuth2 client metadata, it returns None.
		"""
		application_type = client_dict.get("application_type")
		redirect_uris = client_dict.get("redirect_uris")
		grant_types = client_dict.get("grant_types")
		if application_type is not None and len(redirect_uris) > 0 and len(grant_types) > 0:
			return cls(client_dict)
		else:
			return None


	def is_confidential(self) -> bool:
		if self.TokenEndpointAuthMethod not in OAuth2.TokenEndpointAuthMethod:
			raise NotImplementedError(
				"Unsupported token_endpoint_auth_method: {!r}".format(self.TokenEndpointAuthMethod))

		if self.TokenEndpointAuthMethod == OAuth2.TokenEndpointAuthMethod.NONE:
			return False
		else:
			return True


	def rest_get(self) -> dict:
		oauth_dict = {
			"client_id": self.ClientId,
			"client_name": self.ClientName,
			"client_uri": self.ClientUri,
			"redirect_uris": self.RedirectUris,
			"application_type": self.ApplicationType,
			"response_types": self.ResponseTypes,
			"grant_types": self.GrantTypes,
			"token_endpoint_auth_method": self.TokenEndpointAuthMethod,
			"code_challenge_method": self.CodeChallengeMethod,
			"default_max_age": self.DefaultMaxAge,
			"redirect_uri_validation_method": self.RedirectUriValidationMethod,
			"cookie_domain": self.CookieDomain,
			"cookie_webhook_uri": self.CookieWebhookUri,
			"cookie_entry_uri": self.CookieEntryUri,
			"authorize_uri": self.AuthorizeUri,
			"login_uri": self.LoginUri,
			"authorize_anonymous_users": self.AuthorizeAnonymousUsers,
			"anonymous_cid": self.AnonymousCid,
			"session_expiration": self.SessionExpiration
		}

		if self._ClientSecretHash is not None:
			oauth_dict["client_secret"] = True
		if self.ClientSecretExpiresAt is not None:
			oauth_dict["client_secret_expires_at"] = self.ClientSecretExpiresAt

		return oauth_dict
