import logging
import aiohttp
import aiohttp.web
import asab
import asab.web.rest

from ...generic import get_bearer_token_value

#

L = logging.getLogger(__name__)

#


class UserInfoHandler(object):


	def __init__(self, app, oidc_svc):
		self.OpenIdConnectService = oidc_svc

		web_app = app.WebContainer.WebApp
		# The Client sends the UserInfo Request using either HTTP GET or HTTP POST.
		web_app.router.add_get('/openidconnect/userinfo', self.userinfo)
		web_app.router.add_post('/openidconnect/userinfo', self.userinfo)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get('/openidconnect/userinfo', self.userinfo)
		web_app_public.router.add_post('/openidconnect/userinfo', self.userinfo)


	async def userinfo(self, request):
		"""
		OpenID Connect Core 1.0, chapter 5.3. UserInfo Endpoint
		"""

		session = request.Session

		if session is None:
			L.warning("Request for invalid/expired session")
			return self.error_response("invalid_session", "The access token is invalid/expired.")

		# # if authorized get provider for this identity

		userinfo = await self.OpenIdConnectService.build_userinfo(
			session,
			tenant=request.query.get("tenant", "*")
		)

		return asab.web.rest.json_response(request, userinfo)


	def error_response(self, error, error_description):
		"""
		OpenID Connect Core 1.0, 5.3.3. Error Response
		"""
		return aiohttp.web.Response(headers={
			"WWW-Authenticate": "error=\"{}\", error_description=\"{}\"".format(error, error_description)
		}, status=401)
