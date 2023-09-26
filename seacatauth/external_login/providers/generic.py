import json
import re
import urllib.parse
import logging
import contextlib

import asab
import aiohttp
import aiohttp.web
import jwcrypto.jwt

#

L = logging.getLogger(__name__)

#


class GenericOAuth2Login(asab.Configurable):
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
	label=Login via provider.auth
	```
	"""

	Type = None

	def __init__(self, external_login_svc, config_section_name, config=None):
		# TODO: Get the URLs automatically from the discovery_uri (or issuer name)
		super().__init__(config_section_name, config)
		if self.Type is None:
			match = re.match("seacatauth:oauth2:([_a-zA-Z0-9]+)", config_section_name)
			self.Type = match.group(1)

		# Adopt proper OAuth/OpenID terminology
		if "authorize_uri" in self.Config:
			asab.LogObsolete.warning(
				"The 'authorize_uri' config option will be obsoleted. Use 'authorization_endpoint' instead. ",
				struct_data={"eol": "2024-01-31"})
			self.Config["authorization_endpoint"] = self.Config["authorize_uri"]
		if "access_token_uri" in self.Config:
			asab.LogObsolete.warning(
				"The 'access_token_uri' config option will be obsoleted. Use 'token_endpoint' instead. ",
				struct_data={"eol": "2024-01-31"})
			self.Config["token_endpoint"] = self.Config["access_token_uri"]
		if "userinfo_uri" in self.Config:
			asab.LogObsolete.warning(
				"The 'userinfo_uri' config option will be obsoleted. Use 'userinfo_endpoint' instead. ",
				struct_data={"eol": "2024-01-31"})
			self.Config["userinfo_endpoint"] = self.Config["userinfo_uri"]

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

		# Label for "Sign up with {ext_login_provider}" button
		# TODO: Make this i18n-compatible (like login descriptors)
		# TODO: Separate label for "Add external login" button
		self.Label = self.Config.get("label")
		assert self.Label is not None

		# Base URL under which the external login endpoint are available
		public_api_base_url = self.Config.get("public_api_base_url")
		if public_api_base_url is None:
			# Fallback to general public_api_base_url
			public_api_base_url = asab.Config.get("general", "public_api_base_url")

		self.LoginURI = "{}{}".format(
			public_api_base_url.rstrip("/"),
			external_login_svc.ExternalLoginPath.format(ext_login_provider=self.Type)
		)
		self.AddExternalLoginURI = "{}{}".format(
			public_api_base_url.rstrip("/"),
			external_login_svc.AddExternalLoginPath.format(ext_login_provider=self.Type)
		)

	def _get_authorize_uri(self, redirect_uri, state=None):
		query_params = [
			("response_type", "code"),
			("client_id", self.ClientId),
			("scope", self.Scope),
			("redirect_uri", redirect_uri),
			("prompt", "select_account"),
		]
		if state is not None:
			query_params.append(("state", state))
		return "{authorize_uri}?{query_string}".format(
			authorize_uri=self.AuthorizationEndpoint,
			query_string=urllib.parse.urlencode(query_params)
		)

	@contextlib.asynccontextmanager
	async def token_request(self, code, redirect_uri):
		"""
		Send auth code to token request endpoint and return access token
		"""
		request_params = [
			("grant_type", "authorization_code"),
			("code", code),
			("client_id", self.ClientId),
			("redirect_uri", redirect_uri)]
		if self.ClientSecret:
			request_params.append(("client_secret", self.ClientSecret))
		query_string = urllib.parse.urlencode(request_params)

		headers = {
			"content-type": "application/x-www-form-urlencoded"
		}
		async with aiohttp.ClientSession() as session:
			async with session.post(self.TokenEndpoint, data=query_string, headers=headers) as resp:
				if resp.status != 200:
					text = await resp.text()
					L.error("Error response from external auth provider", struct_data={
						"status": resp.status,
						"url": resp.url,
						"text": text
					})
					yield None
				else:
					yield resp

	async def _get_user_info(self, code, redirect_uri):
		async with self.token_request(code, redirect_uri=redirect_uri) as resp:
			if resp is None:
				return None
			token_data = await resp.json()

		if "id_token" not in token_data:
			L.error("Token response does not contain 'id_token'", struct_data={"resp": token_data})
			return None

		id_token = token_data["id_token"]
		await self._prepare_jwks()

		try:
			id_info = jwcrypto.jwt.JWT(jwt=id_token, key=self.Jwks)
			claims = id_info.token.objects.get("payload")
			claims = json.loads(claims)
		except Exception as e:
			L.error("Error reading id_token claims.", struct_data={
				"err": str(e),
				"resp": token_data})
			return None

		user_info = {}
		if "sub" in claims.keys():
			user_info["sub"] = claims["sub"]
		if "email" in claims.keys():
			user_info["email"] = claims["email"]
		if self.Ident in claims.keys():
			user_info["ident"] = claims[self.Ident]
		return user_info

	def get_login_authorize_uri(self, state=None):
		return self._get_authorize_uri(self.LoginURI, state)

	def get_addlogin_authorize_uri(self, state=None):
		return self._get_authorize_uri(self.AddExternalLoginURI, state)

	# TODO: These two methods do the exact same thing. Refactor.
	async def do_external_login(self, code):
		return await self._get_user_info(code, redirect_uri=self.LoginURI)

	async def add_external_login(self, code):
		return await self._get_user_info(code, redirect_uri=self.AddExternalLoginURI)
