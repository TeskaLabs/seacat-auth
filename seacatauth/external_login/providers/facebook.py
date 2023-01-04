import logging
import aiohttp

from .generic import GenericOAuth2Login

#

L = logging.getLogger(__name__)

#


class FacebookOAuth2Login(GenericOAuth2Login):
	"""
	This app must be registered at Facebook:
	https://developers.facebook.com/docs/facebook-login/web

	Redirect URI should be set to the following:
	https://{my_domain}/seacat_auth/public/ext-login/facebook
	https://{my_domain}/seacat_auth/public/ext-login-add/facebook
	"""
	Type = "facebook"
	ConfigDefaults = {
		"authorize_uri": "https://www.facebook.com/v15.0/dialog/oauth",
		"access_token_uri": "https://graph.facebook.com/v15.0/oauth/access_token",
		"userinfo_uri": "https://graph.facebook.com/me",
		"login_redirect_uri": "https://facebook.com/connect/login_success.html",
		"scope": "email,public_profile", 
		"fields": "id,name,email",
		"label": "Sign in with Facebook",
	}

	def __init__(self, external_login_svc, config_section_name):
		super().__init__(external_login_svc, config_section_name)
		self.UserInfoURI = self.Config.get("userinfo_uri")
		self.LoginRedirectURI = self.Config.get("login_redirect_uri")
		self.Scope = self.Config.get("scope")
		self.Fields = self.Config.get("fields")
		assert self.UserInfoURI not in (None, "")

	async def _get_user_info(self, code, redirect_uri):
		"""
		Info is not contained in access_token,
		call to https://graph.facebook.com/me is needed.
		See the Facebook API Explorer here: https://developers.facebook.com/tools/explorer
		"""
		async with self.token_request(code, redirect_uri=redirect_uri) as resp:
			access_token_dict = await resp.json()

		if "access_token" not in access_token_dict:
			L.error("Token response does not contain 'access token'", struct_data={"resp": access_token_dict})
			return None

		access_token = access_token_dict["access_token"]

		qparams = {'fields': self.Fields, 'access_token': access_token}
		async with aiohttp.ClientSession() as session:
			async with session.get(self.UserInfoURI, params=qparams) as resp:
				data = await resp.json()
				if resp.status != 200:
					L.error("Error response from external auth provider", struct_data={
						"status": resp.status,
						"data": data,
						"url": resp.url
					})
					return None

		user_info = {}
		if "id" in data:
			user_info["sub"] = data["id"]
		if "email" in data:
			user_info["email"] = data["email"]

		return user_info
