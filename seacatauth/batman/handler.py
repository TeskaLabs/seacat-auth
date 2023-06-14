import logging

import aiohttp.web

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
		web_app_public = app.PublicWebContainer.WebApp
		self.BatmanService = batman_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_put("/batman/nginx", self.batman_nginx)

		# Public endpoints
		web_app_public.router.add_put("/batman/nginx", self.batman_nginx)


	async def batman_nginx(self, request):
		"""
		Validate Batman cookie and respond with Basic Authorization header

		**Internal endpoint for Nginx auth_request.**
		"""
		cookie_service = self.BatmanService.App.get_service("seacatauth.CookieService")
		cookie_value = cookie_service.get_session_cookie_value(request, request.query.get("client_id"))
		if cookie_value is None:
			return aiohttp.web.HTTPUnauthorized()

		session = await cookie_service.get_session_by_session_cookie_value(cookie_value)
		if session is None or session.Batman is None:
			return aiohttp.web.HTTPUnauthorized()

		return aiohttp.web.HTTPOk(headers={
			"Authorization": "Basic {}".format(session.Batman.Token.decode("ascii"))
		})
