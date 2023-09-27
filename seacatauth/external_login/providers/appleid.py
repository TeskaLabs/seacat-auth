import base64
import json
import logging
import urllib.parse
import jwcrypto.jwt
import jwcrypto.jwk

from typing import Optional
from .generic import GenericOAuth2Login
from ..utils import get_apple_public_key_json_by_key_id

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
	ALLOWED_ISSUER = 'https://appleid.apple.com'

	Type = "appleid"
	ConfigDefaults = {
		"discovery_uri": "https://appleid.apple.com/.well-known/openid-configuration",
		# Apple returns e-mail and username in the response right after OAuth2 /authorize call,
		# so we do not need client_secret at all, but seacat has it as a required parameter, so we intentionally
		# set it to dummy value here.
		"client_secret": "notasecret",
		"authorize_uri": "https://appleid.apple.com/auth/authorize",
		"access_token_uri": "https://appleid.apple.com/auth/token",
		"scope": "name email",
		"label": "Sign in with Apple",
	}

	def __init__(self, external_login_svc, config_section_name, config=None):
		super().__init__(external_login_svc, config_section_name, config)
		self.Scope = self.Config.get("scope")

	def _get_authorize_uri(self, redirect_uri: str, state: Optional[str] = None, nonce: Optional[str] = None) -> str:
		query_params = [
			("response_mode", "form_post"),
			("response_type", "code id_token"),
			("client_id", self.ClientId),
			("scope", self.Scope),
			("redirect_uri", redirect_uri),
		]
		if state is not None:
			query_params.append(("state", state))
		if nonce is not None:
			query_params.append(("nonce", nonce))
		return "{authorize_uri}?{query_string}".format(
			authorize_uri=self.AuthorizeURI,
			query_string=urllib.parse.urlencode(query_params)
		)

	async def _get_user_info(self, auth_provider_response: dict, redirect_uri: str) -> Optional[dict]:
		if auth_provider_response is None or len(auth_provider_response) == 0:
			L.error(
				"Identity provider did not return any authorization data or data is empty",
				struct_data={"resp": auth_provider_response}
			)
			return None

		auth_error = auth_provider_response.get('error')

		if auth_error is not None:
			if auth_error == 'user_cancelled_authorize':
				L.error(
					"User has cancelled authorization with identity provider",
					struct_data={"auth_error": auth_error}
				)
				return None
			else:
				L.error(
					"An unknown error has occurred during authorization flow",
					struct_data={"auth_error": auth_error}
				)
				return None

		id_token = auth_provider_response.get('id_token')  # JSON web token containing the user’s identity information

		try:
			# 'user' is available only after the first successful authorization with Apple identity provider. Any
			#  subsequent authorizations will not have this property. To get it again, user must de-authorize the app
			#  from his Apple ID account and then authorize again using Sign with Apple.
			#  Moreover, user's firstName and lastName are contained only in this 'user' property. They are not included
			#  in the id_token at all.
			# 'user' contains the following: # firstName, lastName, email
			user = self._parse_user_data(auth_provider_response.get('user'))

			verified_claims = self._get_verified_claims(id_token=id_token)

			user_info = {
				"sub": verified_claims.get('sub'),
				"email": verified_claims.get('email'),
				"is_proxy_email": bool(verified_claims.get('is_private_email')),
				"nonce": verified_claims.get('nonce'),
			}

			if user is not None:
				user_info.update(
					{
						"first_name": user.get('name', {}).get('firstName'),
						"last_name": user.get('name', {}).get('lastName'),
					}
				)

			return user_info

		except jwcrypto.jws.InvalidJWSSignature:
			L.error("Given id_token's JWS signature does not match")
			return None
		except jwcrypto.jwt.JWTExpired as e:
			L.error("Given id_token is expired ('exp' claim > now())")
			return None

	def _get_verified_claims(self, id_token: str) -> dict:
		apple_signing_key_id = self._get_signing_key_id_from_jwt_header(jwt=id_token)
		apple_signing_public_key_json = get_apple_public_key_json_by_key_id(apple_signing_key_id)
		apple_signing_key = jwcrypto.jwk.JWK(**apple_signing_public_key_json)

		claims_to_verify = {
			'aud': self.ClientId,
			'iss': self.ALLOWED_ISSUER,
		}

		token = jwcrypto.jwt.JWT(jwt=id_token, key=apple_signing_key, check_claims=claims_to_verify)
		claims = json.loads(token.claims)

		return claims

	def _parse_user_data(self, user_json: Optional[str]) -> Optional[dict]:
		if user_json is None:
			return None

		return json.loads(user_json)

	def _get_signing_key_id_from_jwt_header(self, jwt: str) -> Optional[str]:
		encoded_jwt_header, _ = jwt.split('.', 1)
		jwt_header_content = self._base64_decode_jwt_token_part(encoded_jwt_header)

		return jwt_header_content.get('kid')

	def _base64_decode_jwt_token_part(self, encoded_jwt_part) -> Optional[dict]:
		encoded_jwt_part += '=' * (-len(encoded_jwt_part) % 4)  # add padding
		decoded = base64.b64decode(encoded_jwt_part).decode("utf-8")
		return json.loads(decoded)