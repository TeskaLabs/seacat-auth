import logging
import aiohttp
import aiohttp.web
import asab
import asab.web.rest
import asab.web.auth
import asab.web.tenant

from ... import generic
from ... import exceptions


L = logging.getLogger(__name__)


class UserInfoHandler(object):
	"""
	OAuth 2.0 UserInfo

	---
	tags: ["OAuth 2.0 / OpenID Connect"]
	"""

	def __init__(self, app, oidc_svc):
		self.OpenIdConnectService = oidc_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get(self.OpenIdConnectService.UserInfoPath, self.userinfo)
		web_app.router.add_post(self.OpenIdConnectService.UserInfoPath, self.userinfo)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get(self.OpenIdConnectService.UserInfoPath, self.userinfo)
		web_app_public.router.add_post(self.OpenIdConnectService.UserInfoPath, self.userinfo)


	@asab.web.auth.noauth
	@asab.web.tenant.allow_no_tenant
	async def userinfo(self, request):
		"""
		OAuth 2.0 UserInfo Endpoint

		OpenID Connect Core 1.0, chapter 5.3. UserInfo Endpoint
		"""

		token_value = generic.get_bearer_token_value(request)
		if token_value is None:
			L.warning("Invalid or missing Bearer token")
			return aiohttp.web.HTTPBadRequest()

		try:
			session = await self.OpenIdConnectService.get_session_by_id_token(token_value)
		except ValueError:
			try:
				session = await self.OpenIdConnectService.get_session_by_access_token(token_value)
			except exceptions.SessionNotFoundError:
				L.log(asab.LOG_NOTICE, "Authentication required")
				return self.error_response("invalid_token", "Access token or cookie is invalid.")

		userinfo = await self.OpenIdConnectService.build_userinfo(session)

		return asab.web.rest.json_response(request, userinfo)


	def error_response(self, error, error_description):
		"""
		OpenID Connect Core 1.0, 5.3.3. Error Response
		"""
		return aiohttp.web.Response(headers={
			"WWW-Authenticate": "error=\"{}\", error_description=\"{}\"".format(error, error_description)
		}, status=401)
