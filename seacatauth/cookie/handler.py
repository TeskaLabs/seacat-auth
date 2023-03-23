import logging
import secrets

import aiohttp
import aiohttp.web
import asab.web.rest

from ..generic import nginx_introspection
from .utils import set_cookie, delete_cookie
from ..client import validate_redirect_uri
from ..openidconnect.utils import TokenRequestErrorResponseCode

#

L = logging.getLogger(__name__)

#


class CookieHandler(object):
	"""
	Cookie grants and validation

	# Example with cookie entrypoint
	```nginx
	# Define introspection cache
	proxy_cache_path on keys_zone=my_app_auth_responses:1m max_size=2m;

	# Define upstreams
	upstream my_app_api {...}
	upstream auth_api {...}

	# Proxy server
	server {
		...

		# Cookie-protected location
		location /my_app {
			auth_request /_my_app_introspection;

			# Let the auth request rewrite the "Authorization" and the "Cookie"
			# headers to prevent auth token leaks
			auth_request_set      $authorization $upstream_http_authorization;
			proxy_set_header      Authorization $authorization;
			auth_request_set      $cookie $upstream_http_cookie;
			proxy_set_header      Cookie $cookie;

			# Extract the "X-State" header from auth request response and insert it in the error page Authorize URI
			auth_request_set      $x_state $upstream_http_x_state;
			error_page 401        /auth/api/openidconnect/authorize?response_type=code&scope=openid%20cookie%20profile&client_id=my-protected-app&state=$x_state&redirect_uri=https://example.app.loc:8443/my_app_callback;

			rewrite ^/my_app(/(.*))? /$2 break;
			proxy_pass http://my_app_api;
		}

		# Cookie introspection endpoint
		location = /_my_app_introspection {
			internal;
			proxy_method          POST;
			proxy_set_body        "$http_authorization";
			proxy_set_header      X-Request-Uri "$scheme://$host:$server_port$request_uri";
			proxy_pass            http://auth_api/cookie/nginx?client_id=my-protected-app;
			proxy_ignore_headers  Cache-Control Expires Set-Cookie;

			# Successful introspection responses should be cached
			proxy_cache           my_app_auth_responses;
			proxy_cache_key       $http_authorization;
			proxy_cache_lock      on;
			proxy_cache_valid     200 30s;
		}

		# Cookie dispenser
		location /my_app_callback {
			proxy_method          POST;
			proxy_set_header      Content-Type "application/x-www-form-urlencoded";
			proxy_set_body        "client_id=my-protected-app&grant_type=authorization_code&code=$arg_code&state=$arg_state";
			proxy_pass            http://auth_api/cookie/entry;
		}
	}
	```
	"""

	def __init__(self, app, cookie_svc, session_svc, credentials_svc):
		self.App = app
		self.CookieService = cookie_svc
		self.SessionService = session_svc
		self.CredentialsService = credentials_svc
		self.RBACService = app.get_service("seacatauth.RBACService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_post("/cookie/nginx", self.nginx)
		web_app.router.add_post("/cookie/nginx/anonymous", self.nginx_anonymous)
		web_app.router.add_post("/cookie/entry", self.bouncer)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_post("/cookie/nginx", self.nginx)
		web_app_public.router.add_post("/cookie/nginx/anonymous", self.nginx_anonymous)
		web_app_public.router.add_post("/cookie/entry", self.bouncer)


	async def nginx(self, request):
		"""
		**Internal endpoint for Nginx auth_request.**
		Authenticate (and optionally authorize) the incoming request by its Cookie + Client ID and respond with
		corresponding ID token. If the auth fails, respond with 401 or 403.

		Optionally check for resource access and/or add requested user info to headers.

		---
		parameters:
		-	name: X-Request-Uri
			in: header
			description:
				Original request URI. In case of auth failure (401 or 403), it can be internally stored during the
				authorization process and then used for redirection to the original location. If this header is
				present, the response will include `X-State` header, which should be added to the OAuth Authorize query.
		-	name: verify
			in: query
			description: Resources to authorize
			schema:
				type: array
				items:
					type: string
					default: my-app:access
		responses:
			200:
				description: Request successfully authenticated (and authorized)
				headers:
					Authorization:
						description: Bearer <JWT_ID_TOKEN>
			401:
				description: Authentication failed
				headers:
					X-State:
						description:
							Random string which should be passed in the OAuth Authorize request's `state` query
							parameter to ensure correct redirection after successful authorization.
							*This header is only present if the request contains an `X-Request-Uri` header
							with a redirect URI that is valid for the Client.*
			403:
				description:
					Authorization failed because of the End-User's or the Client's insufficient permissions.
		"""
		client_id = request.query.get("client_id")
		if client_id is None:
			raise ValueError("No 'client_id' parameter specified in anonymous introspection query.")

		# TODO: Also check query for scope and validate it

		session = await self._authenticate_request(request, client_id)
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
			response = await self._set_response_state_query(request, response, client_id)
			delete_cookie(self.App, response)
			return response

		return response


	async def nginx_anonymous(self, request):
		"""
		**Internal endpoint for Nginx auth_request.**
		Authenticate (and optionally authorize) the incoming request by its Cookie + Client ID and respond with
		corresponding ID token. If the auth fails with 401, initialize an "unauthenticated" anonymous session
		and set a session cookie in the response.

		Optionally check for resource access and/or add requested user info to headers.

		---
		parameters:
		-	name: cid
			in: query
			description: Credentials ID which will be used to create the anonymous sessions
			required: true
			schema:
				type: string
				default: mongodb:default:abc123def456
		"""
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

		session = await self._authenticate_request(request, client_id)
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


	async def bouncer(self, request):
		"""
		Exchange authorization code for cookie and redirect to the original request URI,
		which was stored by the failed introspection call.

		Used as callback endpoint for OAuth Authorize request. Together with cookie introspection, this endpoint
		replaces the obsolete `seacatauth.bouncer` module.

		---
		parameters:
		-	name: client_id
			in: query
			description: OAuth Client ID
			required: true
		-	name: state
			in: query
			description: State string generated before the authorize call
			required: true
		-	name: grant_type
			in: query
			description: OAuth Grant Type
			required: true
			schema:
				enum: ["authorization_code"]
		-	name: code
			in: query
			description: OAuth Authorization code returned by the authorize endpoint
			required: true
		"""
		client_svc = self.App.get_service("seacatauth.ClientService")

		query = await request.post()

		client_id = query.get("client_id")
		if client_id is None:
			L.error("No 'client_id' specified in cookie entrypoint query.")
			return asab.web.rest.json_response(
				request, {"error": TokenRequestErrorResponseCode.InvalidRequest}, status=400)
		try:
			client = await client_svc.get(client_id)
		except KeyError:
			L.error("Client not found.", struct_data={"client_id": client_id})
			return asab.web.rest.json_response(
				request, {"error": TokenRequestErrorResponseCode.InvalidClient}, status=400)

		grant_type = query.get("grant_type")
		if grant_type != "authorization_code":
			L.error("Grant type not supported.", struct_data={"grant_type": grant_type})
			return asab.web.rest.json_response(
				request, {"error": TokenRequestErrorResponseCode.UnsupportedGrantType}, status=400)

		# Use the code to get session ID
		code = query.get("code")
		if code in (None, ""):
			L.warning("Empty or missing 'code' parameter in query.", struct_data={"client_id": client_id})
			return asab.web.rest.json_response(
				request, {"error": TokenRequestErrorResponseCode.InvalidRequest}, status=400)
		session = await self.CookieService.get_session_by_authorization_code(code)
		if session is None:
			L.warning("Session not found: Authorization code invalid or expired.", struct_data={"client_id": client_id})
			return asab.web.rest.json_response(
				request, {"error": TokenRequestErrorResponseCode.InvalidGrant}, status=400)

		# Retrieve the original request URI by the state
		state = query.get("state")
		try:
			redirect_uri = await self.CookieService.get_redirect_uri(client_id, state)
		except KeyError:
			L.warning("State matched no redirect URI.", struct_data={"client_id": client_id, "state": state})
			return asab.web.rest.json_response(
				request, {"error": TokenRequestErrorResponseCode.InvalidGrant}, status=400)

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


	async def _authenticate_request(self, request, client_id=None):
		return await self.CookieService.get_session_by_sci(request, client_id)


	async def _set_response_state_query(self, request, response, client_id):
		client_svc = self.App.get_service("seacatauth.ClientService")
		redirect_uri = request.headers.get("X-Request-Uri")
		if redirect_uri is not None:
			# Validate redirect URI
			client = await client_svc.get(client_id)
			if validate_redirect_uri(
					redirect_uri, client["redirect_uris"], client.get("validation_method")
			):
				state = await self.CookieService.store_redirect_uri(redirect_uri, client_id)
				response.headers.add("X-State", state)
			else:
				L.warning("Redirect URI not valid for client.", struct_data={
					"client_id": client_id, "redirect_uri": redirect_uri})
				response = aiohttp.web.HTTPForbidden()
		return response
