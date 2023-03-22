import logging
import secrets

import aiohttp
import aiohttp.web

from ..generic import nginx_introspection
from .utils import set_cookie, delete_cookie
from ..client import validate_redirect_uri

#

L = logging.getLogger(__name__)

#


class CookieHandler(object):


	def __init__(self, app, cookie_svc, session_svc, credentials_svc):
		self.App = app
		self.CookieService = cookie_svc
		self.SessionService = session_svc
		self.CredentialsService = credentials_svc
		self.RBACService = app.get_service("seacatauth.RBACService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_post('/cookie/nginx', self.nginx)
		web_app.router.add_post('/cookie/nginx/anonymous', self.nginx_anonymous)
		web_app.router.add_post('/cookie/entry', self.cookie_authorize_callback)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_post('/cookie/nginx', self.nginx)
		web_app_public.router.add_post('/cookie/nginx/anonymous', self.nginx_anonymous)
		web_app_public.router.add_post('/cookie/entry', self.cookie_authorize_callback)


	async def authenticate_request(self, request, client_id=None):
		return await self.CookieService.get_session_by_sci(request, client_id)


	async def nginx(self, request):
		"""
		Validate the session cookie and exchange it for a Bearer token.
		Optionally check for resource access.
		Add requested user info to headers.

		Example Nginx setup:
		```nginx
		# Protected location
		location /my-app {
			auth_request /_cookie_introspect;
			auth_request_set      $authorization $upstream_http_authorization;
			proxy_set_header      Authorization $authorization;
			proxy_pass            http://my-app:8080
		}

		# Introspection endpoint
		location = /_cookie_introspect {
			internal;
			proxy_method          POST;
			proxy_set_body        "$http_authorization";
			proxy_pass            http://seacat-auth-svc:8081/cookie/nginx?add=credentials&resource=my-app:access;
		}
		```
		"""
		client_svc = self.App.get_service("seacatauth.ClientService")

		client_id = request.query.get("client_id")
		if client_id is None:
			raise ValueError("No 'client_id' parameter specified in anonymous introspection query.")

		# TODO: Also check query for scope and validate it

		session = await self.authenticate_request(request, client_id)
		if session is None:
			response = aiohttp.web.HTTPUnauthorized()
		elif session.Authentication.IsAnonymous:
			L.warning("Regular cookie introspection does not allow anonymous user access.", struct_data={
				"client_id": client_id, "cid": session.Credentials.Id})
			response = aiohttp.web.HTTPUnauthorized()
		else:
			try:
				response = await nginx_introspection(request, session, self.App)
			except Exception as e:
				L.warning("Request authorization failed: {}".format(e), exc_info=True)
				response = aiohttp.web.HTTPUnauthorized()

		if response.status_code != 200:
			state = secrets.token_urlsafe(16)
			redirect_uri = request.headers.get("X-Request-Uri")
			# Validate redirect URI
			client = await client_svc.get(client_id)
			if validate_redirect_uri(
				redirect_uri, client["redirect_uris"], client.get("validation_method")
			):
				self.CookieService.TrampolineStorage[state] = redirect_uri
				response.headers.add("X-State", state)
			else:
				L.warning("Redirect URI not valid for client.", struct_data={
					"client_id": client_id, "redirect_uri": redirect_uri})
				response = aiohttp.web.HTTPForbidden()
			delete_cookie(self.App, response)
			return response

		return response


	async def nginx_anonymous(self, request):
		client_svc = self.App.get_service("seacatauth.ClientService")

		anonymous_cid = request.query.get("cid")
		if anonymous_cid is None:
			L.error("No 'cid' parameter specified in anonymous introspection query.")
			return aiohttp.web.HTTPBadRequest()
		anonymous_session_created = False

		client_id = request.query.get("client_id")
		if client_id is None:
			L.error("No 'client_id' parameter specified in anonymous introspection query.")
			return aiohttp.web.HTTPBadRequest()
		try:
			client = await client_svc.get(client_id)
		except KeyError:
			L.error("Client not found.", struct_data={"client_id": client_id})
			return aiohttp.web.HTTPBadRequest()

		scope = request.query.get("scope", "")
		if len(scope) > 0:
			scope = scope.split(" ")
		else:
			scope = ["cookie"]

		session = await self.authenticate_request(request, client_id)
		if session is None:
			# Create a new root session with anonymous_cid and a cookie
			from_info = [request.remote]
			forwarded_for = request.headers.get("X-Forwarded-For")
			if forwarded_for is not None:
				from_info.extend(forwarded_for.split(", "))
			session = await self.CookieService.AuthenticationService.create_anonymous_session(
				anonymous_cid, client_id, scope, from_info=from_info)
			anonymous_session_created = True

		if session is None:
			response = aiohttp.web.HTTPUnauthorized()
		else:
			try:
				response = await nginx_introspection(request, session, self.App)
			except Exception as e:
				L.warning("Request authorization failed: {}".format(e), exc_info=True)
				response = aiohttp.web.HTTPUnauthorized()

		cookie_domain = client.get("cookie_domain") or None

		if response.status_code != 200:
			delete_cookie(self.App, response)
			return response

		if anonymous_session_created:
			set_cookie(self.App, response, session, cookie_domain)

		return response


	async def cookie_authorize_callback(self, request):
		"""
		Exchange authorization code for cookie and redirect afterwards.

		Together with cookie introspection, this endpoint replaces the obsolete `seacatauth.bouncer` module.
		"""
		client_svc = self.App.get_service("seacatauth.ClientService")

		query = await request.post()

		client_id = query.get("client_id")
		if client_id is None:
			L.error("No 'client_id' specified in cookie entrypoint query.")
			return aiohttp.web.HTTPBadRequest()
		try:
			client = await client_svc.get(client_id)
		except KeyError:
			L.error("Client not found.", struct_data={"client_id": client_id})
			return aiohttp.web.HTTPBadRequest()

		grant_type = query.get("grant_type")
		if grant_type != "authorization_code":
			L.error("Grant type not supported.", struct_data={"grant_type": grant_type})
			return aiohttp.web.HTTPBadRequest()

		state = query.get("state")
		redirect_uri = self.CookieService.TrampolineStorage.pop(state, None)
		if redirect_uri is None:
			L.error("Empty or missing redirect URI.", struct_data={"client_id": client_id, "state": state})
			return aiohttp.web.HTTPBadRequest()

		# Use the code to get session ID
		code = query.get("code")
		if code in (None, ""):
			L.warning("Empty or missing 'code' parameter in query.", struct_data={"client_id": client_id})
			return aiohttp.web.HTTPBadRequest()
		session = await self.CookieService.get_session_by_authorization_code(code)
		if session is None:
			L.warning("Session not found: Authorization code invalid or expired.", struct_data={"client_id": client_id})
			return aiohttp.web.HTTPBadRequest()

		# Construct the response
		if client.get("cookie_domain") not in (None, ""):
			cookie_domain = client["cookie_domain"]
		else:
			cookie_domain = self.CookieService.RootCookieDomain

		response = aiohttp.web.HTTPFound(
			redirect_uri,
			headers={
				"Refresh": '0;url=' + redirect_uri,
				"Location": redirect_uri,
			},
			content_type="text/html",
			text="<!doctype html>\n<html lang=\"en\">\n<head></head><body>...</body>\n</html>\n"
		)

		# TODO: Verify that the request came from the correct domain

		set_cookie(self.App, response, session, cookie_domain)

		# TODO: Set additional client cookies (obtained via synchronous HTTP request to a preconfigured endpoint)

		return response
