import logging
import urllib.parse
import aiohttp

from .generic import GenericOAuth2Login

#

L = logging.getLogger(__name__)

#


class GitHubOAuth2Login(GenericOAuth2Login):
	"""
	This app must be registered at Github:
	https://github.com/settings/developers

	Redirect URI should be set to the following:
	https://{my_domain}/seacat_auth
	"""
	Type = "github"
	ConfigDefaults = {
		# Github does not implement OpenID Connect, only OAuth. There is no OpenID discovery_uri.
		"authorization_endpoint": "https://github.com/login/oauth/authorize",
		"token_endpoint": "https://github.com/login/oauth/access_token",
		"userinfo_endpoint": "https://api.github.com/user",
		"scope": "",  # Scope is not required
		"label": "Sign in with Github",
		"ident": "login",
	}

	def __init__(self, external_login_svc, config_section_name):
		super().__init__(external_login_svc, config_section_name)
		self.UserInfoEndpoint = self.Config.get("userinfo_endpoint")
		assert self.UserInfoEndpoint not in (None, "")

	async def _get_user_info(self, code, redirect_uri):
		"""
		Info is not contained in access_token,
		call to https://api.github.com/user is needed.
		"""
		async with self.token_request(code, redirect_uri=redirect_uri) as resp:
			response_text = await resp.text()

		params = urllib.parse.parse_qs(response_text)
		access_token = params.get("access_token")

		if access_token is None:
			L.error("Token response does not contain access token", struct_data={"response": params})

		access_token = access_token[0]

		headers = {
			"Authorization": "bearer {}".format(access_token)
		}

		async with aiohttp.ClientSession() as session:
			async with session.get(self.UserInfoEndpoint, headers=headers) as resp:
				data = await resp.json()
				if resp.status != 200:
					L.error("Error response from external auth provider", struct_data={
						"status": resp.status,
						"data": data
					})
					return None

		user_info = {}
		if "id" in data:
			user_info["sub"] = data["id"]
		if "email" in data:
			user_info["email"] = data["email"]
		if self.Ident in data:
			user_info["ident"] = data[self.Ident]

		return user_info
