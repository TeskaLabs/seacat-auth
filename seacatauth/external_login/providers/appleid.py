import json
import logging
import typing
import urllib.parse

from typing import Optional
from .generic import GenericOAuth2Login

#

L = logging.getLogger(__name__)

#


class AppleIDOAuth2Login(GenericOAuth2Login):
	"""
	This app ("Service ID" in Apple terminology) must be registered at Apple developer site:
	https://developer.apple.com/account/resources/identifiers/list/serviceId

	Redirect URI should be set to the following:
	https://{my_domain}/seacat_auth/public/ext-login/appleid
	https://{my_domain}/seacat_auth/public/ext-login-add/appleid

	Docs for "Sign in with Apple": https://developer.apple.com/documentation/sign_in_with_apple/
	"""

	Type = "appleid"
	ConfigDefaults = {
		"issuer": "https://appleid.apple.com",
		"discovery_uri": "https://appleid.apple.com/.well-known/openid-configuration",
		# AppleID supports Hybrid authentication flow where the user data is returned directly in the authorize response,
		# hence no token request and no client secret is needed.
		"authorization_endpoint": "https://appleid.apple.com/auth/authorize",
		"token_endpoint": "https://appleid.apple.com/auth/token",
		"jwks_uri": "https://appleid.apple.com/auth/keys",
		"scope": "name email",
		"label": "AppleID",
	}

	def __init__(self, external_login_svc, config_section_name, config=None):
		super().__init__(external_login_svc, config_section_name, config)
		self.Scope = self.Config.get("scope")

	def get_authorize_uri(
		self, redirect_uri: typing.Optional[str] = None,
		state: typing.Optional[str] = None,
		nonce: typing.Optional[str] = None
	) -> str:
		query_params = [
			("response_mode", "form_post"),
			("response_type", "code id_token"),
			("client_id", self.ClientId),
			("scope", self.Scope),
			("redirect_uri", redirect_uri or self.CallbackUrl),
		]
		if state is not None:
			query_params.append(("state", state))
		if nonce is not None:
			query_params.append(("nonce", nonce))
		return "{authorize_uri}?{query_string}".format(
			authorize_uri=self.AuthorizationEndpoint,
			query_string=urllib.parse.urlencode(query_params)
		)

	async def get_user_info(self, authorize_data: dict, expected_nonce: str | None = None) -> typing.Optional[dict]:
		auth_error = authorize_data.get("error")
		if auth_error is not None:
			if auth_error == "user_cancelled_authorize":
				L.error(
					"User has cancelled authorization with identity provider",
					struct_data={"provider": self.Type, "auth_error": auth_error}
				)
				return None
			else:
				L.error(
					"An unknown error has occurred during authorization flow",
					struct_data={"provider": self.Type, "auth_error": auth_error}
				)
				return None

		id_token = authorize_data.get("id_token")
		verified_claims = self._get_verified_claims(id_token, expected_nonce)
		if not verified_claims:
			return None

		user_info = {
			"sub": str(verified_claims.get("sub")),
			"email": verified_claims.get("email"),
			"is_proxy_email": bool(verified_claims.get("is_private_email")),
			"nonce": verified_claims.get("nonce"),
		}

		# Add optional user data
		user_data = self._parse_user_data(authorize_data.get("user"))
		if user_data is not None:
			user_info.update(user_data)

		return user_info

	def _parse_user_data(self, user_json: Optional[str]) -> Optional[dict]:
		"""
		The 'user' data is only available in the request after the first successful authorization with
		Apple identity provider. Any subsequent authorizations will not have this property. To get it again, the user
		must de-authorize the app from his Apple ID account and then authorize again using Sign with Apple.
		Moreover, user's firstName and lastName are contained only in this 'user' property. They are not included
		in the id_token at all. 'user' contains the following attributes: firstName, lastName, email
		"""
		if user_json is None:
			return None
		user_json = json.loads(user_json)

		name = user_json.get("name")
		if name is None:
			return None

		return {
			"first_name": name.get("firstName"),
			"last_name": name.get("lastName")
		}
