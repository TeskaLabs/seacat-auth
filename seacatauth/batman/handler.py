import logging
import asab

import aiohttp.web

from .. import exceptions
from .. import generic


#

L = logging.getLogger(__name__)

#


class BatmanHandler(object):
	"""
	Batman (Basic auth)

	Translates Seacat Auth cookies into Basic auth headers for applications that only support Basic auth (Kibana, Grafana).
	"""

	def __init__(self, app, batman_svc):
		self.App = app
		self.BatmanService = batman_svc
		web_app = app.WebContainer.WebApp
		web_app.router.add_post("/nginx/introspect/batman", self.batman_nginx)

		# TODO: Insecure, back-compat only - remove after 2024-03-31
		if asab.Config.getboolean("seacatauth:introspection", "_enable_insecure_legacy_endpoints", fallback=False):
			web_app_public = app.PublicWebContainer.WebApp
			web_app_public.router.add_post("/batman/nginx", self.batman_nginx)
			web_app_public.router.add_put("/batman/nginx", self.batman_nginx)


	async def batman_nginx(self, request):
		"""
		Validate Batman cookie and respond with Basic Authorization header

		**Internal endpoint for Nginx auth_request.**

		---
		tags: ["Nginx"]
		"""
		cookie_service = self.App.get_service("seacatauth.CookieService")
		oidc_service = self.App.get_service("seacatauth.OpenIdConnectService")

		client_id = request.query.get("client_id")
		if client_id is None:
			raise ValueError("No 'client_id' parameter specified in Batman introspection query")

		token_value = generic.get_bearer_token_value(request)
		if token_value is None:
			token_value = generic.get_access_token_value_from_websocket(request)

		if token_value is not None:
			session = await oidc_service.get_session_by_access_token(token_value)
			if session is None:
				L.log(asab.LOG_NOTICE, "Session not found by access token")
				return aiohttp.web.HTTPUnauthorized()
		else:
			try:
				session = await cookie_service.get_session_by_request_cookie(request, client_id)
			except exceptions.NoCookieError:
				L.log(asab.LOG_NOTICE, "No client cookie in request", struct_data={"client_id": client_id})
				return aiohttp.web.HTTPUnauthorized()
			except exceptions.SessionNotFoundError:
				L.log(asab.LOG_NOTICE, "Session not found by client cookie", struct_data={"client_id": client_id})
				return aiohttp.web.HTTPUnauthorized()

		if session.Batman is None:
			# This should not happen - session is not of Batman type
			L.error("Session not authorized for Batman")
			return aiohttp.web.HTTPUnauthorized()

		return aiohttp.web.HTTPOk(headers={
			"Authorization": "Basic {}".format(session.Batman.Token.decode("ascii"))
		})
