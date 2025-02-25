import logging
import aiohttp
import aiohttp.web
import asab

from ... import AuditLogger, exceptions
from ...generic import get_bearer_token_value


L = logging.getLogger(__name__)


class SessionHandler(object):
	"""
	OAuth 2.0 Session management

	---
	tags: ["OAuth 2.0 / OpenID Connect"]
	"""

	def __init__(self, app, oidc_svc, session_svc):
		self.App = app

		self.OpenIdConnectService = oidc_svc
		self.SessionService = session_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get(self.OpenIdConnectService.EndSessionPath, self.session_logout)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get(self.OpenIdConnectService.EndSessionPath, self.session_logout)


	async def session_logout(self, request):
		"""
		OpenID Connect end session endpoint

		https://openid.net/specs/openid-connect-rpinitiated-1_0.html
		"""
		token_value = get_bearer_token_value(request)
		if token_value is None:
			L.warning("Invalid or missing Bearer token")
			return aiohttp.web.HTTPBadRequest()

		try:
			session = await self.OpenIdConnectService.get_session_by_id_token(token_value)
		except ValueError:
			try:
				session = await self.OpenIdConnectService.get_session_by_access_token(token_value)
			except exceptions.SessionNotFoundError:
				session = None
		if session is None:
			return aiohttp.web.HTTPNotFound()

		if session.Session.ParentSessionId is not None:
			try:
				parent_session = await self.SessionService.get(session.Session.ParentSessionId)
			except KeyError:
				parent_session = None
		else:
			parent_session = None

		# Delete the root session which will also remove this session
		await self.SessionService.delete(parent_session.Session.Id)

		AuditLogger.log(asab.LOG_NOTICE, "Logout successful", struct_data={
			"cid": session.Credentials.Id,
			"sid": session.SessionId,
			"psid": parent_session.SessionId,
			"token_type": "access_token"
		})

		return aiohttp.web.Response(text="", content_type="text/html")
