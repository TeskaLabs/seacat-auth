import logging
import asab

import aiohttp.web

from seacatauth import exceptions

#

L = logging.getLogger(__name__)

#


class BatmanHandler(object):
	"""
	Batman (Basic auth)

	Translates Seacat Auth cookies into Basic auth headers for applications that only support Basic auth (Kibana, Grafana).

	---
	tags: ["Batman (Basic auth)"]
	"""

	def __init__(self, app, batman_svc):
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
		"""
		cookie_service = self.BatmanService.App.get_service("seacatauth.CookieService")

		client_id = request.query.get("client_id")
		if client_id is None:
			raise ValueError("No 'client_id' parameter specified in Batman introspection query.")

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
