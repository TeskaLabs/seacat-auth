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
		session = await self.OpenIdConnectService.get_session_from_authorization(request)
		if session is None:
			return aiohttp.web.HTTPNotFound()

		await self.SessionService.delete(session.SessionId)
		return aiohttp.web.Response(text="", content_type="text/html")
