import logging
import aiohttp
import aiohttp.web

from ...generic import get_bearer_token_value

#

L = logging.getLogger(__name__)

#


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
		web_app.router.add_get('/openidconnect/logout', self.session_logout)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get('/openidconnect/logout', self.session_logout)


	async def session_logout(self, request):
		"""
		OAuth 2.0 Session Logout
		"""
		token_value = get_bearer_token_value(request)
		if token_value is None:
			L.warning("Invalid or missing Bearer token")
			return aiohttp.web.HTTPBadRequest()

		try:
			session = await self.OpenIdConnectService.get_session_by_id_token(token_value)
		except ValueError:
			session = await self.OpenIdConnectService.get_session_by_access_token(token_value)
		if session is None:
			return aiohttp.web.HTTPNotFound()

		if session.Session.ParentSessionId is not None:
			try:
				parent_session = await self.SessionService.get(session.Session.ParentSessionId)
			except KeyError:
				parent_session = None
		else:
			parent_session = None

		if parent_session is not None:
			# Delete the root session which will also remove this session
			await self.SessionService.delete(parent_session.Session.Id)
		else:
			# Back compat: This can occur with old sessions
			L.warning("OIDC session has no parent session", struct_data={
				"sid": session.Session.Id,
				"parent_sid": session.Session.ParentSessionId,
			})
			await self.SessionService.delete(session.Session.Id)

		return aiohttp.web.Response(text="", content_type="text/html")
