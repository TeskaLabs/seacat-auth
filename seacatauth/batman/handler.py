import logging
import asab
import asab.web.auth
import asab.web.tenant
import aiohttp.web

from .. import exceptions
from .. import generic


L = logging.getLogger(__name__)


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


	@asab.web.auth.noauth
	@asab.web.tenant.allow_no_tenant
	async def batman_nginx(self, request):
		"""
		Cookie introspection for basic auth apps

		**Internal endpoint for Nginx auth_request**

		Validate Seacat Auth cookie and respond with Basic Authorization header.

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
			try:
				session = await oidc_service.get_session_by_access_token(token_value)
			except exceptions.SessionNotFoundError:
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
