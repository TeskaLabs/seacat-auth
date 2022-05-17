import logging

import aiohttp
import aiohttp.web

#

L = logging.getLogger(__name__)

#


class SessionHandler(object):


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
		session = await self.OpenIdConnectService.get_session_from_authorization_header(request)
		if session is None:
			return aiohttp.web.HTTPNotFound()

		if session.Session.ParentId is not None:
			try:
				parent_session = await self.SessionService.get(session.Session.ParentId)
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
				"parent_sid": session.Session.ParentId,
			})
			await self.SessionService.delete(session.Session.Id)

		return aiohttp.web.Response(text="", content_type="text/html")
