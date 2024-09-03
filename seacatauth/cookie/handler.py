import logging
import uuid

import aiohttp
import aiohttp.web
import asab.web.rest
import asab.exceptions

from .. import exceptions, AuditLogger
from .. import generic
from ..contextvars import AccessIps
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
			error_page 401        /auth/api/openidconnect/authorize?response_type=code&scope=openid%20cookie%20profile&client_id=my-protected-app&state=$x_state&redirect_uri=https://my.app.test/my_app_callback;

			rewrite ^/my_app(/(.*))? /$2 break;
			proxy_pass http://my_app_api;
		}

		# Cookie introspection endpoint
		location = /_my_app_introspection {
			internal;
			proxy_method          POST;
			proxy_set_body        "$http_authorization";
			proxy_set_header      X-Request-Uri "$scheme://$host$request_uri";
			proxy_pass            http://auth_api/nginx/introspect/cookie?client_id=my-protected-app;
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

	---
	tags: ["HTTP Cookies"]
	"""

	def __init__(self, app, cookie_svc, session_svc, credentials_svc):
		self.App = app
		self.CookieService = cookie_svc
		self.SessionService = session_svc
		self.CredentialsService = credentials_svc
		self.RBACService = app.get_service("seacatauth.RBACService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_post("/nginx/introspect/cookie", self.nginx)
		web_app.router.add_post("/nginx/introspect/cookie/anonymous", self.nginx_anonymous)
		web_app.router.add_get("/cookie/entry", self.cookie_get)
		web_app.router.add_post("/cookie/entry", self.cookie_post)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get("/cookie/entry", self.cookie_get)
		web_app_public.router.add_post("/cookie/entry", self.cookie_post)

		# TODO: Insecure, back-compat only - remove after 2024-03-31
		if asab.Config.getboolean("seacatauth:introspection", "_enable_insecure_legacy_endpoints", fallback=False):
			web_app_public.router.add_post("/cookie/nginx", self.nginx)
			web_app_public.router.add_post("/cookie/nginx/anonymous", self.nginx_anonymous)


	async def nginx(self, request):
		"""
		Cookie introspection

		**Internal endpoint for Nginx auth_request**

		Authenticate (and optionally authorize) the incoming request by its Cookie + Client ID and respond with
		corresponding ID token. If the auth fails, respond with 401 or 403.

		Optionally check for resource access and/or add requested user info to headers.

		---
		tags: ["Nginx"]
		parameters:
		-	name: X-Request-Uri
			in: header
			description:
				Original request URI. In case of auth failure (401 or 403), it can be internally stored during the
				authorization process and then used for redirection to the original location. If this header is
				present, the response will include `X-State` header, which should be added to the OAuth Authorize query.
			schema:
				type: string
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
						schema:
							type: string
			401:
				description: Authentication failed
			403:
				description:
					Authorization failed because of the End-User's or the Client's insufficient permissions.
		"""
		client_id = request.query.get("client_id")
		if client_id is None:
			raise ValueError("No 'client_id' parameter specified in cookie introspection query.")

		# TODO: Also check query for scope and validate it

		session = await self._authenticate_request(request, client_id)
		if session is None:
			response = aiohttp.web.HTTPUnauthorized()
		elif session.is_anonymous():
			L.log(asab.LOG_NOTICE, "Anonymous user access not allowed", struct_data={
				"client_id": client_id, "cid": session.Credentials.Id})
			response = aiohttp.web.HTTPUnauthorized()
		else:
			try:
				response = await generic.nginx_introspection(request, session, self.App)
			except Exception as e:
				L.exception("Introspection failed: {}".format(e))
				response = aiohttp.web.HTTPUnauthorized()

		if response.status_code != 200:
			self.CookieService.delete_session_cookie(response, client_id)
			return response

		return response


	async def nginx_anonymous(self, request):
		"""
		Anonymous (guest) cookie introspection

		**Internal endpoint for Nginx auth_request**

		Authenticate (and optionally authorize) the incoming request by its Cookie + Client ID and respond with
		corresponding ID token. If the auth fails with 401, initialize an "unauthenticated" anonymous session
		and set a session cookie in the response.

		This requires that the client has a valid "anonymous_cid" attribute configured.

		Optionally check for resource access and/or add requested user info to headers.

		---
		tags: ["Nginx"]
		parameters:
		-	name: client_id
			in: query
			description: ID of the Client who requested the introspection
			required: true
			schema:
				type: string
				default: my-application
		"""
		client_svc = self.App.get_service("seacatauth.ClientService")

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

		# Get anonymous_cid from client
		anonymous_cid = client.get("anonymous_cid")
		if anonymous_cid is None:
			L.error("Client has no 'anonymous_cid' configured.", struct_data={"client_id": client_id})
			return aiohttp.web.HTTPBadRequest()

		# Validate anonymous anonymous_cid
		try:
			await self.CredentialsService.get(anonymous_cid)
		except KeyError:
			L.error("Credentials for anonymous access not found.", struct_data={
				"cid": anonymous_cid, "client_id": client_id})
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
			track_id = uuid.uuid4().bytes
			session = await self.CookieService.create_anonymous_cookie_client_session(
				anonymous_cid, client, scope,
				track_id=track_id,
				from_info=from_info)
			anonymous_session_created = True

		if session is None:
			response = aiohttp.web.HTTPUnauthorized()
		else:
			try:
				response = await generic.nginx_introspection(request, session, self.App)
			except Exception as e:
				L.exception("Introspection failed: {}".format(e))
				response = aiohttp.web.HTTPUnauthorized()

		cookie_domain = client.get("cookie_domain") or None

		if response.status_code != 200:
			self.CookieService.delete_session_cookie(response, client_id)
			return response

		if anonymous_session_created:
			self.CookieService.set_session_cookie(
				response=response,
				cookie_value=session.Cookie.Id,
				client_id=session.OAuth2.ClientId,
				cookie_domain=cookie_domain
			)

			# Trigger webhook and add custom HTTP headers
			try:
				data = await self._fetch_webhook_data(client, session)
				if data is not None:
					response.headers.update(data.get("response_headers", {}))
			except exceptions.ClientResponseError as e:
				L.error("Webhook responded with error.", struct_data={
					"status": e.Status, "text": e.Data})
				return asab.web.rest.json_response(
					request, {"error": TokenRequestErrorResponseCode.InvalidRequest}, status=400)

		return response


	async def cookie_get(self, request):
		"""
		Exchange authorization code for cookie and redirect to specified redirect URI.

		---
		parameters:
		-	name: client_id
			in: query
			description: OAuth Client ID
			required: true
			schema:
				type: string
		-	name: redirect_uri
			in: query
			description: Original request URI
			required: true
			schema:
				type: string
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
			schema:
				type: string
		"""
		params = request.query
		return await self._cookie(request, params)


	async def cookie_post(self, request):
		"""
		Exchange authorization code for cookie and redirect to specified redirect URI.

		---
		requestBody:
			content:
				application/x-www-form-urlencoded:
					schema:
						type: object
						properties:
							client_id:
								type: string
								enum: ["authorization_code", "refresh_token"]
								description: The type of grant being requested.
							redirect_uri:
								type: string
								description: The destination to redirect to.
							grant_type:
								type: string
								enum: ["authorization_code"]
								description: OAuth Grant Type.
							code:
								type: string
								description: The authorization code returned by the authorization server.
						required:
							- grant_type
							- code
							- client_id
							- redirect_uri
		"""
		params = await request.post()
		return await self._cookie(request, params)


	async def _cookie(self, request, parameters):
		"""
		Exchange authorization code for cookie and redirect to specified redirect URI.
		"""
		for param in {"client_id", "grant_type", "code"}:
			if param not in parameters:
				AuditLogger.log(
					asab.LOG_NOTICE,
					"Cookie request denied: No '{}' in request query".format(param),
					struct_data={"access_ips": AccessIps.get()}
				)
				return asab.web.rest.json_response(
					request, {"error": TokenRequestErrorResponseCode.InvalidRequest}, status=400)

		cookie, redirect_uri, client_headers = await self.CookieService.process_cookie_request(
			request,
			client_id=parameters["client_id"],
			grant_type=parameters["grant_type"],
			code=parameters["code"],
		)

		response = aiohttp.web.HTTPFound(
			redirect_uri,
			headers={
				"Refresh": '0;url=' + redirect_uri,
				"Location": redirect_uri,
			},
			content_type="text/html",
			text="<!doctype html>\n<html lang=\"en\">\n<head></head><body>...</body>\n</html>\n"
		)

		# Add headers from webhook
		response.headers.update(client_headers)

		# Add Seacat Auth cookie
		self.CookieService.set_session_cookie(
			response=response,
			client_id=parameters["client_id"],
			cookie_value=cookie["value"],
			cookie_domain=cookie.get("domain"),
		)

		return response


	async def _authenticate_request(self, request, client_id=None):
		"""
		Locate session by request cookie
		"""
		try:
			session = await self.CookieService.get_session_by_request_cookie(request, client_id)
		except exceptions.NoCookieError:
			L.log(asab.LOG_NOTICE, "No client cookie found in request", struct_data={"client_id": client_id})
			return None
		except exceptions.SessionNotFoundError:
			L.log(asab.LOG_NOTICE, "Session not found by client cookie", struct_data={"client_id": client_id})
			return None

		return session
