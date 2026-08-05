import logging
import datetime

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
		self.App = app
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
					# Token is not a seacat-auth session ID token.
					# Try to validate it as an internal ASAB auth token via the AuthService's ID token provider,
					# which has the cluster's internal auth public key registered via InternalAuth.
					userinfo = await self._build_userinfo_from_internal_token(request)
					if userinfo is None:
						L.log(asab.LOG_NOTICE, "Authentication required.")
						return asab.exceptions.NotAuthenticatedError(
							error="invalid_token",
							error_description="Invalid ID token.",
							realm="asab",
							scope=["openid"],
						)
					return asab.web.rest.json_response(request, userinfo)
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

		userinfo = await self.OpenIdConnectService.build_userinfo(session)

		return asab.web.rest.json_response(request, userinfo)


	async def _build_userinfo_from_internal_token(self, request):
		"""
		Validate the request's Bearer token using the ASAB AuthService's ID token provider
		and build a userinfo response from the validated claims.

		This handles internal cluster auth tokens that are signed with the cluster's internal private key.
		These tokens are not associated with any seacat-auth session, so we build the userinfo
		directly from the JWT claims.
		"""
		auth_service = self.App.get_service("asab.AuthService")
		if auth_service is None:
			L.warning("AuthService not available; cannot validate internal auth token.")
			return None

		try:
			authz = await auth_service.authorize_request(request)
		except asab.exceptions.NotAuthenticatedError:
			return None
		except Exception as e:
			L.warning("Unexpected error during internal auth token validation.", struct_data={
				"error": str(e),
			})
			return None

		if authz is None:
			return None

		claims = authz._Claims
		L.log(asab.LOG_NOTICE, "Request authenticated via internal auth token.", struct_data={
			"iss": claims.get("iss"),
			"azp": claims.get("azp"),
		})

		# The internal token represents a service (e.g. "asab-iris"), not a user session.
		# We use the authorized party (azp) as the subject identifier.
		service_id = claims.get("azp", "internal:unknown")

		# Build a minimal userinfo response from the internal auth token claims.
		userinfo = {
			"iss": self.OpenIdConnectService.Issuer,
			"sub": claims.get("sub") or service_id,
			"iat": claims.get("iat"),
			"exp": claims.get("exp"),
			"sid": service_id,
			# Include username fields needed by the web application
			"username": service_id,
			"preferred_username": service_id,
		}

		if claims.get("azp") is not None:
			userinfo["azp"] = claims["azp"]

		if claims.get("aud") is not None:
			userinfo["aud"] = claims["aud"]

		# Include resource authorization info so the web app knows
		# this token carries superuser privileges
		if claims.get("resources") is not None:
			userinfo["resources"] = claims["resources"]

		return userinfo
