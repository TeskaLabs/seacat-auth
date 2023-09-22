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
		"authorize_uri": "https://github.com/login/oauth/authorize",
		"access_token_uri": "https://github.com/login/oauth/access_token",
		"userinfo_uri": "https://api.github.com/user",
		"user_emails_uri": "https://api.github.com/user/emails",
		"scope": "user:email",  # Scope is not required
		"label": "Sign in with Github",
		"ident": "login",
	}

	def __init__(self, external_login_svc, config_section_name):
		super().__init__(external_login_svc, config_section_name)
		self.UserInfoURI = self.Config.get("userinfo_uri")
		self.UserEmailsURI = self.Config.get("user_emails_uri")
		assert self.UserInfoURI not in (None, "")

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
		authorization = "bearer {}".format(access_token)

		async with aiohttp.ClientSession() as session:
			async with session.get(self.UserInfoURI, headers={"Authorization": authorization}) as resp:
				user_data = await resp.json()
				if resp.status != 200:
					L.error("Error response from external auth provider", struct_data={
						"status": resp.status,
						"data": user_data})
					return None

		email = user_data.get("email")
		if not email:
			email = await self._get_user_email(authorization)

		user_info = {}
		if "id" in user_data:
			user_info["sub"] = user_data["id"]
		if self.Ident in user_data:
			user_info["ident"] = user_data[self.Ident]
		if email:
			user_info["email"] = email

		return user_info

	async def _get_user_email(self, authorization):
		"""
		Get Github user's primary email address.
		"""
		async with aiohttp.ClientSession() as session:
			async with session.get(self.UserEmailsURI, headers={"Authorization": authorization}) as resp:
				emails = await resp.json()
				if resp.status != 200:
					L.error("Error response from external auth provider", struct_data={
						"status": resp.status,
						"data": emails})
					return None

		for email_data in emails:
			if email_data.get("primary"):
				return email_data.get("email")
