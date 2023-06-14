import logging
import base64
import secrets


import asab
import aiohttp.web

#

L = logging.getLogger(__name__)

#


asab.Config.add_defaults(
	{
		"batman": {
			"enabled": "false",
			"oidc_url": "http://localhost:8082/openidconnect",  # The base URL for OpenID Connect
		}
	}
)


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
		web_app.router.add_get("/batman", self.batman_oidc_authorize_callback)

		# Public endpoints
		web_app_public.router.add_put("/batman/nginx", self.batman_nginx)
		web_app_public.router.add_get("/batman", self.batman_oidc_authorize_callback)

		self.OIDC_URL = asab.Config["batman"]["oidc_url"]

		# TODO: Refresh/remove expiring grants
		self.Grants = {}


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


	async def batman_oidc_authorize_callback(self, request):
		"""
		Exchange OAuth authorization code for Batman cookie
		"""
		code = request.query.get("code")
		if code is None:
			L.warning("Code has not been presented")
			return aiohttp.web.HTTPUnauthorized()

		target_location = request.query.get("state")
		if code is None:
			L.warning("State has not been presented")
			return aiohttp.web.HTTPUnauthorized()

		# Exchange code for access token
		token_query = {
			"grant_type": "batman",
			"code": code,
		}
		async with aiohttp.ClientSession() as session:
			async with session.post(self.OIDC_URL + "/token", data=token_query) as resp:
				if resp.status != 200:
					# The authorization of the access failed
					return aiohttp.web.HTTPUnauthorized()

				batman_token = await resp.json()

				username = batman_token["username"]
				if ":" in username:
					L.warning("Username contains ':', that will not work with BatMan")
					return aiohttp.web.HTTPUnauthorized()

				password = self.BatmanService.generate_password(batman_token["cid"])

				batman_token["ba"] = base64.b64encode((
					"{}:{}".format(username, password)
				).encode("ascii")).decode("ascii")

		bid = secrets.token_urlsafe()
		self.Grants[bid] = batman_token

		response = aiohttp.web.HTTPSeeOther(location=target_location)
		response.set_cookie(self.BatmanService.CookieName, bid)
		return response
