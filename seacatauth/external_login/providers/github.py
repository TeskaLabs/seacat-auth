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
		# Github uses a custom OAuth implementation. There is no OpenID discovery_uri.
		"authorization_endpoint": "https://github.com/login/oauth/authorize",
		"token_endpoint": "https://github.com/login/oauth/access_token",
		"userinfo_endpoint": "https://api.github.com/user",
		"user_emails_endpoint": "https://api.github.com/user/emails",
		"scope": "user:email",  # Scope is not used
		"label": "Sign in with Github",
	}

	def __init__(self, external_login_svc, config_section_name):
		super().__init__(external_login_svc, config_section_name)
		self.UserInfoEndpoint = self.Config.get("userinfo_endpoint")
		assert self.UserInfoEndpoint not in (None, "")
		self.UserEmailsURI = self.Config.get("user_emails_endpoint")

	async def get_user_info(self, authorize_data):
		"""
		User info is not contained in token response,
		call to https://api.github.com/user is needed.
		"""
		code = authorize_data.get("code")
		if code is None:
			L.error("Code parameter not provided in authorize response.", struct_data={
				"provider": self.Type,
				"query": dict(authorize_data)})
			return None

		async with self.token_request(code, redirect_uri=self.CallbackUri) as resp:
			response_text = await resp.text()

		params = urllib.parse.parse_qs(response_text)
		access_token = params.get("access_token")

		if access_token is None:
			L.error("Token response does not contain access token.", struct_data={
				"provider": self.Type, "response": params})

		access_token = access_token[0]
		authorization = "bearer {}".format(access_token)

		async with aiohttp.ClientSession() as session:
			async with session.get(self.UserInfoEndpoint, headers={"Authorization": authorization}) as resp:
				user_data = await resp.json()
				if resp.status != 200:
					L.error("Error response from external auth provider.", struct_data={
						"provider": self.Type,
						"status": resp.status,
						"data": user_data})
					return None

		email = user_data.get("email")
		if not email:
			email = await self._get_user_email(authorization)

		user_info = {}
		if "id" in user_data:
			user_info["sub"] = user_data["id"]
		if email:
			user_info["email"] = email
		if "login" in user_data:
			user_info["login"] = user_data["login"]
		if "name" in user_data:
			user_info["name"] = user_data["name"]

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
