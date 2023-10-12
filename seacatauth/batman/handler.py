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
		self.BatmanService = batman_svc
		web_app = app.WebContainer.WebApp
		web_app.router.add_post("/nginx/batman", self.batman_nginx)


	async def batman_nginx(self, request):
		"""
		Validate Batman cookie and respond with Basic Authorization header

		**Internal endpoint for Nginx auth_request.**
		"""
		cookie_service = self.BatmanService.App.get_service("seacatauth.CookieService")

		client_id = request.query.get("client_id")
		if client_id is None:
			raise ValueError("No 'client_id' parameter specified in Batman introspection query.")

		session = await cookie_service.get_session_by_request_cookie(request, request.query.get("client_id"))
		if session is None or session.Batman is None:
			return aiohttp.web.HTTPUnauthorized()

		return aiohttp.web.HTTPOk(headers={
			"Authorization": "Basic {}".format(session.Batman.Token.decode("ascii"))
		})
