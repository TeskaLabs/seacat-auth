import logging
import typing
import urllib.parse
import aiohttp

from .generic import GenericOAuth2Login

#

L = logging.getLogger(__name__)

#


class FacebookOAuth2Login(GenericOAuth2Login):
	"""
	This app must be registered at Facebook:
	https://developers.facebook.com/docs/facebook-login/web

	# Facebook uses a custom OAuth implementation. The flow is described here:
	https://developers.facebook.com/docs/facebook-login/guides/advanced/manual-flow

	Redirect URI should be set to the following:
	https://{my_domain}/seacat-auth/public/ext-login/facebook
	https://{my_domain}/seacat-auth/public/ext-login-add/facebook
	"""
	Type = "facebook"
	ConfigDefaults = {
		# Facebook uses a custom OAuth implementation. There is no OpenID discovery_uri.
		"authorization_endpoint": "https://www.facebook.com/v15.0/dialog/oauth",
		"token_endpoint": "https://graph.facebook.com/v15.0/oauth/access_token",
		"userinfo_endpoint": "https://graph.facebook.com/me",
		"response_type": "code",
		"scope": "public_profile",
		"fields": "id,name,email",
		"label": "Sign in with Facebook",
	}

	def __init__(self, external_login_svc, config_section_name):
		super().__init__(external_login_svc, config_section_name)
		self.UserInfoEndpoint = self.Config.get("userinfo_endpoint")
		self.ResponseType = self.Config.get("response_type")
		self.Scope = self.Config.get("scope")
		self.Fields = self.Config.get("fields")
		assert self.UserInfoEndpoint not in (None, "")

	def get_authorize_uri(
		self, redirect_uri: str,
		state: typing.Optional[str] = None,
		nonce: typing.Optional[str] = None
	):
		query_params = [
			("client_id", self.ClientId),
			("response_type", self.ResponseType),
			("scope", self.Scope),
			("redirect_uri", redirect_uri),
		]
		if state is not None:
			query_params.append(("state", state))
		return "{authorize_uri}?{query_string}".format(
			authorize_uri=self.AuthorizationEndpoint,
			query_string=urllib.parse.urlencode(query_params)
		)

	async def _get_user_info(self, authorize_data, redirect_uri):
		"""
		Info is not contained in token response, call to userinfo_endpoint is needed.
		See the Facebook API Explorer here: https://developers.facebook.com/tools/explorer
		"""
		code = authorize_data.get("code")
		if code is None:
			L.error("Code parameter not provided in authorize response.", struct_data={
				"provider": self.Type,
				"query": dict(authorize_data)})
			return None

		async with self.token_request(code, redirect_uri=redirect_uri) as resp:
			token_data = await resp.json()

		if "access_token" not in token_data:
			L.error("Token response does not contain 'access_token'.", struct_data={
				"provider": self.Type, "resp": token_data})
			return None

		access_token = token_data["access_token"]

		qparams = {"fields": self.Fields, "access_token": access_token}
		async with aiohttp.ClientSession() as session:
			async with session.get(self.UserInfoEndpoint, params=qparams) as resp:
				data = await resp.json()
				if resp.status != 200:
					L.error("Error response from external auth provider.", struct_data={
						"provider": self.Type,
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
		if "name" in data:
			user_info["name"] = data["name"]

		return user_info
