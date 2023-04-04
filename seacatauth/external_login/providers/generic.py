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


class GenericOAuth2Login(asab.ConfigObject):
	"""
	Generic OAuth2 login provider

	Example config:
	```conf
	[seacatauth:oauth2:auth_provider_name]
	; ALL fields must be configured
	client_id=308u2fXEBUTolb.provider.auth
	client_secret=5TfIjab8EZtixx3XkmFLfdXiHxkU2KlU

	authorize_uri=https://provider.auth/login/oauth/authorize
	access_token_uri=https://provider.auth/login/oauth/access_token

	scope=openidconnect
	label=Login via provider.auth
	```
	"""

	Type = None

	def __init__(self, external_login_svc, config_section_name, config=None):
		super().__init__(config_section_name, config)
		if self.Type is None:
			match = re.match("seacatauth:oauth2:([_a-zA-Z0-9]+)", config_section_name)
			self.Type = match.group(1)

		self.ClientId = self.Config.get("client_id")
		assert self.ClientId is not None

		self.ClientSecret = self.Config.get("client_secret")
		assert self.ClientSecret is not None

		self.AuthorizeURI = self.Config.get("authorize_uri")
		assert self.AuthorizeURI is not None

		self.AccessTokenURI = self.Config.get("access_token_uri")
		assert self.AccessTokenURI is not None

		self.Scope = self.Config.get("scope")
		assert self.Scope is not None

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
			authorize_uri=self.AuthorizeURI,
			query_string=urllib.parse.urlencode(query_params)
		)

	@contextlib.asynccontextmanager
	async def token_request(self, code, redirect_uri):
		"""
		Send auth code to token request endpoint and return access token
		"""
		query_string = urllib.parse.urlencode([
			("grant_type", "authorization_code"),
			("code", code),
			("client_id", self.ClientId),
			("client_secret", self.ClientSecret),
			("redirect_uri", redirect_uri)
		])
		headers = {
			"content-type": "application/x-www-form-urlencoded"
		}
		async with aiohttp.ClientSession() as session:
			async with session.post(self.AccessTokenURI, data=query_string, headers=headers) as resp:
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
			access_token_dict = await resp.json()

		if "id_token" not in access_token_dict:
			L.error("Token response does not contain 'id_token'", struct_data={"at_resp": access_token_dict})
			return None

		id_token = access_token_dict["id_token"]

		try:
			id_info = jwcrypto.jwt.JWT(jwt=id_token)
			payload = id_info.token.objects.get("payload")
			data_dict = json.loads(payload)
		except Exception as e:
			L.error("Error reading id_token payload", struct_data={
				"err": str(e),
				"at_resp": access_token_dict,
			})
			return None

		user_info = {}
		if "sub" in data_dict.keys():
			user_info["sub"] = data_dict["sub"]
		if "email" in data_dict.keys():
			user_info["email"] = data_dict["email"]
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
