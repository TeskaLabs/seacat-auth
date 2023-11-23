import logging
import aiohttp
import aiohttp.web
import asab
import asab.web.rest

from ... import generic

#

L = logging.getLogger(__name__)

#


class UserInfoHandler(object):
	"""
	OAuth 2.0 UserInfo

	---
	tags: ["OAuth 2.0 / OpenID Connect"]
	"""

	def __init__(self, app, oidc_svc):
		self.OpenIdConnectService = oidc_svc

		web_app = app.WebContainer.WebApp
		# The Client sends the UserInfo Request using either HTTP GET or HTTP POST.
		web_app.router.add_get(self.OpenIdConnectService.UserInfoPath, self.userinfo)
		web_app.router.add_post(self.OpenIdConnectService.UserInfoPath, self.userinfo)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get(self.OpenIdConnectService.UserInfoPath, self.userinfo)
		web_app_public.router.add_post(self.OpenIdConnectService.UserInfoPath, self.userinfo)


	async def userinfo(self, request):
		"""
		OAuth 2.0 UserInfo Endpoint

		OpenID Connect Core 1.0, chapter 5.3. UserInfo Endpoint
		"""
		token_value = generic.get_bearer_token_value(request)
		if token_value is not None:
			try:
				session = await self.OpenIdConnectService.get_session_by_id_token(token_value)
			except ValueError:
				session = await self.OpenIdConnectService.get_session_by_access_token(token_value)
			if session is None:
				L.log(asab.LOG_NOTICE, "Authentication required: Bearer token is invalid")
				return self.error_response("invalid_token", "Bearer token is invalid")
		elif request.Session is None:
			L.log(asab.LOG_NOTICE, "Authentication required: Invalid or no cookie in request")
			return self.error_response("invalid_token", "Invalid or no cookie in request")
		else:
			session = request.Session

		userinfo = await self.OpenIdConnectService.build_userinfo(session)

		return asab.web.rest.json_response(request, userinfo)


	def error_response(self, error, error_description):
		"""
		OpenID Connect Core 1.0, 5.3.3. Error Response
		"""
		return aiohttp.web.Response(headers={
			"WWW-Authenticate": "error=\"{}\", error_description=\"{}\"".format(error, error_description)
		}, status=401)
