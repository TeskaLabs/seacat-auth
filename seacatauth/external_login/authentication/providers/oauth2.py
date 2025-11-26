import asyncio
import datetime
import json
import secrets
import typing
import urllib.parse
import logging
import contextlib
import aiohttp
import aiohttp.web
import jwcrypto.jwt
import jwcrypto.jwk
import jwcrypto.jws

from ...exceptions import ExternalLoginError
from ....exceptions import AccessDeniedError
from .abc import ExternalAuthProviderABC


L = logging.getLogger(__name__)
_JWKS_REFRESH_MAX_AGE_SECONDS = 10 * 60


class OAuth2AuthProvider(ExternalAuthProviderABC):
	"""
	Generic OAuth2 (OpenID) login provider

	Example config:
	```conf
	[seacatauth:oauth2:auth_provider_name]
	; ALL fields must be configured
	client_id=308u2fXEBUTolb.provider.auth
	client_secret=5TfIjab8EZtixx3XkmFLfdXiHxkU2KlU

	issuer=https://provider.auth/login
	discovery_uri=https://provider.auth/login/.well-known/openid-configuration
	jwks_uri=https://provider.auth/login/.well-known/jwks.json
	authorization_endpoint=https://provider.auth/login/oauth/authorize
	token_endpoint=https://provider.auth/login/oauth/token
	userinfo_endpoint=https://provider.auth/login/oauth/userinfo

	scope=openid name email
	label=My Local Auth
	```

	Seacat Auth external login callback endpoint (/public/ext-login/callback) must be allowed as a redirect URIs
	in the OAuth client settings at the external login account provider.
	The full callback URL is canonically in the following format:
	https://{my_domain}/api/seacat-auth/public/ext-login/callback
	"""

	NonceLength = 32  # Length of the nonce to generate, or 0 to disable nonce

	def __init__(self, external_authentication_svc, config_section_name, config=None):
		super().__init__(external_authentication_svc, config_section_name, config)

		# TODO: Get the URLs automatically from the discovery_uri (or issuer name)
		self.Issuer = self.Config.get("issuer")
		self.DiscoveryUri = self.Config.get("discovery_uri")
		self.JwksUri = self.Config.get("jwks_uri")

		self.AuthorizationEndpoint = self.Config.get("authorization_endpoint")
		assert self.AuthorizationEndpoint is not None

		self.TokenEndpoint = self.Config.get("token_endpoint")
		assert self.TokenEndpoint is not None

		self.ClientId = self.Config.get("client_id")
		assert self.ClientId is not None

		self.ClientSecret = self.Config.get("client_secret")

		self.Scope = self.Config.get("scope")
		assert self.Scope is not None

		self.Ident = self.Config.get("ident", "email")
		assert self.Ident is not None

		if "nonce_length" in self.Config:
			self.NonceLength = self.Config.getint("nonce_length")

		self.JwkSet = None
		self.JwkSetLastUpdated = None
		self._jwks_lock = asyncio.Lock()

		# The URL to return to after successful external login
		# Configurable for debugging purposes
		if "_callback_url" in self.Config:
			self.CallbackUrl = self.Config.get("_callback_url")
		else:
			self.CallbackUrl = external_authentication_svc.CallbackUrlTemplate.format(provider_type=self.Type)


	async def initialize(self, app):
		await self._prepare_jwks()


	async def _on_housekeeping(self, event_name):
		await self._prepare_jwks(max_age=0)


	async def prepare_auth_request(self, state: dict, **kwargs) -> typing.Tuple[dict, aiohttp.web.Response]:
		if self.NonceLength:
			nonce = secrets.token_urlsafe(self.NonceLength)
			state["nonce"] = nonce
		else:
			nonce = None

		auth_uri = self._get_authorize_uri(
			state=state["state_id"],
			nonce=nonce
		)
		return state, aiohttp.web.HTTPFound(auth_uri)


	async def process_auth_callback(self, request: aiohttp.web.Request, payload: dict, state: dict, **kwargs) -> dict:
		return await self._get_user_info(payload, expected_nonce=state.get("nonce"))


	async def _prepare_jwks(self, max_age: int | None = None):
		"""
		Fetch and prepare the JWK set from the identity provider

		Args:
			max_age: Number of seconds.
				If set, the JWK set will only be refreshed if it is older than this value.
				If None and the JWK set is already loaded, no action is taken.
		"""
		if not self.JwksUri:
			return
		async with self._jwks_lock:
			if self.JwkSet:
				if max_age is None:
					return
				if (
					self.JwkSetLastUpdated is not None
					and datetime.datetime.now(datetime.UTC) - self.JwkSetLastUpdated < datetime.timedelta(seconds=max_age)
				):
					return

			try:
				async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
					async with session.get(self.JwksUri) as resp:
						if resp.status != 200:
							text = await resp.text()
							L.error(
								"Failed to fetch server JWK set: External identity provider responded with error.",
								struct_data={
									"provider": self.Type,
									"status": resp.status,
									"url": resp.url,
									"text": text,
								}
							)
							return
						jwks = await resp.text()
			except aiohttp.ClientError as e:
				L.error("Failed to fetch server JWK set: {}".format(e), struct_data={"type": self.Type})
				return
			except asyncio.TimeoutError:
				L.error("Failed to fetch server JWK set: Connection timed out")
				return

			self.JwkSet = jwcrypto.jwk.JWKSet.from_json(jwks)
			self.JwkSetLastUpdated = datetime.datetime.now(datetime.UTC)
			L.info("Identity provider public JWK set loaded.", struct_data={"type": self.Type})


	def _get_authorize_uri(
		self,
		state: typing.Optional[str] = None,
		nonce: typing.Optional[str] = None
	):
		query_params = [
			("response_type", "code"),
			("client_id", self.ClientId),
			("scope", self.Scope),
			("redirect_uri", self.CallbackUrl),
			("prompt", "select_account"),
		]
		if state is not None:
			query_params.append(("state", state))
		if nonce is not None:
			query_params.append(("nonce", nonce))
		return "{authorize_uri}?{query_string}".format(
			authorize_uri=self.AuthorizationEndpoint,
			query_string=urllib.parse.urlencode(query_params)
		)


	@contextlib.asynccontextmanager
	async def token_request(self, code: str, redirect_uri: str | None = None):
		"""
		Send auth code to token request endpoint and return access token
		"""
		request_params = [
			("grant_type", "authorization_code"),
			("code", code),
			("client_id", self.ClientId),
			("redirect_uri", redirect_uri or self.CallbackUrl)]
		if self.ClientSecret:
			request_params.append(("client_secret", self.ClientSecret))
		query_string = urllib.parse.urlencode(request_params)

		headers = {
			"content-type": "application/x-www-form-urlencoded"
		}
		async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
			async with session.post(self.TokenEndpoint, data=query_string, headers=headers) as resp:
				if resp.status != 200:
					text = await resp.text()
					L.error("Error response from external auth provider.", struct_data={
						"status": resp.status,
						"url": resp.url,
						"text": text
					})
					raise ExternalLoginError("Token request failed.")
				else:
					yield resp


	async def _get_user_info(self, authorize_data: dict, expected_nonce: str | None = None) -> typing.Optional[dict]:
		"""
		Obtain the authenticated user's profile info, with the claims normalized to be in line with
		OpenID UserInfo response.

		Supported claims:
		- sub (required)
		- preferred_username
		- email
		- phone_number
		- name
		- first_name
		- last_name
		"""
		error = authorize_data.get("error")
		if error is not None:
			error_description = authorize_data.get("error_description", "")
			L.error("Error response from authorize endpoint.", struct_data={
				"provider": self.Type,
				"error": error,
				"error_description": error_description,
				"query": dict(authorize_data)
			})
			if error == "access_denied":
				raise AccessDeniedError("User denied access.")
			raise ExternalLoginError("Error response from authorize endpoint: {} {}".format(
				error, error_description))

		code = authorize_data.get("code")
		if code is None:
			L.error("Code parameter not provided in authorize response.", struct_data={
				"provider": self.Type,
				"query": dict(authorize_data)})
			raise ExternalLoginError("No 'code' parameter in request.")

		async with self.token_request(code) as resp:
			token_data = await resp.json()

		if "id_token" not in token_data:
			L.error("Token response does not contain 'id_token'", struct_data={
				"provider": self.Type, "resp": token_data})
			raise ExternalLoginError("No 'id_token' in token response.")

		id_token = token_data["id_token"]
		id_token_claims = await self._get_verified_claims(id_token, expected_nonce)
		user_info = self._user_data_from_id_token_claims(id_token_claims)
		user_info["sub"] = str(user_info["sub"])
		return user_info


	def _user_data_from_id_token_claims(self, id_token_claims: dict):
		user_info = {
			k: v
			for k, v in id_token_claims.items()
			if k in {
				"iss", "sub", "email", "phone_number", "preferred_username", "name", "email_verified",
				"phone_number_verified", "nonce"
			} and v is not None
		}
		return user_info


	async def _get_verified_claims(self, id_token, expected_nonce: str | None = None) -> dict:
		await self._prepare_jwks()
		check_claims = self._get_claims_to_verify()
		if expected_nonce:
			check_claims["nonce"] = expected_nonce
		for attempt in range(2):
			try:
				id_token = jwcrypto.jwt.JWT(jwt=id_token, key=self.JwkSet, check_claims=check_claims)
				claims = json.loads(id_token.claims)
				return claims
			except jwcrypto.jws.InvalidJWSSignature:
				L.error("Invalid ID token signature.", struct_data={"provider": self.Type})
				raise ExternalLoginError("Invalid ID token signature.")
			except jwcrypto.jwt.JWTExpired:
				L.error("Expired ID token.", struct_data={"provider": self.Type})
				raise ExternalLoginError("Expired ID token.")
			except jwcrypto.jwt.JWTMissingKey:
				if attempt == 0:
					# JWK set might be outdated, try to refresh it
					await self._prepare_jwks(max_age=_JWKS_REFRESH_MAX_AGE_SECONDS)
					continue
				L.error("Missing key in JWK set after refresh.", struct_data={"provider": self.Type})
				raise ExternalLoginError("Missing key in JWK set.")
			except Exception as e:
				L.error("Error reading ID token claims.", struct_data={
					"provider": self.Type, "error": str(e)})
				raise ExternalLoginError("Error reading ID token claims.")


	def _get_claims_to_verify(self) -> dict:
		return {
			"iss": self.Issuer,
			"aud": self.ClientId
		}
