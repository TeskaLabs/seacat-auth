import logging
import asab
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.exceptions

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
		self.CookieService = app.get_service("seacatauth.CookieService")

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
		if token_value is not None:
			try:
				# Non-canonical
				session = await self.OpenIdConnectService.get_session_by_id_token(token_value)
				if session is None:
					L.log(asab.LOG_NOTICE, "Authentication required.")
					return asab.exceptions.NotAuthenticatedError(
						error="invalid_token",
						error_description="Invalid ID token.",
						realm="asab",
						scope=["openid"],
					)
			except ValueError:
				try:
					# Canonical
					session = await self.OpenIdConnectService.get_session_by_access_token(token_value)
				except exceptions.SessionNotFoundError:
					L.log(asab.LOG_NOTICE, "Authentication required.")
					return asab.exceptions.NotAuthenticatedError(
						error="invalid_token",
						error_description="Missing or invalid access token.",
						realm="asab",
						scope=["openid"],
					)

		else:
			try:
				# Non-canonical
				session = await self.CookieService.get_session_by_request_cookie(request)
			except (exceptions.NoCookieError, exceptions.SessionNotFoundError):
				L.log(asab.LOG_NOTICE, "Authentication required.")
				return asab.exceptions.NotAuthenticatedError(
					error="invalid_token",
					error_description="Missing or invalid cookie.",
					realm="asab",
					scope=["openid"],
				)

		if "openid" not in session.OAuth2.Scope:
			L.log(asab.LOG_NOTICE, "Insufficient scope.")
			return asab.exceptions.NotAuthenticatedError(
				error="insufficient_scope",
				error_description="Required scope 'openid' is missing.",
				realm="asab",
				scope=["openid"],
			)

		userinfo = await self.OpenIdConnectService.build_userinfo(session)

		return asab.web.rest.json_response(request, userinfo)
