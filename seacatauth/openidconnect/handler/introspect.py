import datetime
import urllib
import logging
import aiohttp.web
import asab
import asab.contextvars
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.utils

from ... import exceptions
from ...generic import (
	nginx_introspection,
	get_access_token_value_from_websocket,
	get_token_from_authorization_header,
	fingerprint,
)


L = logging.getLogger(__name__)


class TokenIntrospectionHandler(object):
	"""
	OAuth 2.0 Token Introspection

	https://tools.ietf.org/html/rfc7662

	---
	tags: ["OAuth 2.0 / OpenID Connect"]
	"""

	def __init__(self, app, oidc_svc, credentials_svc):
		self.CredentialsService = credentials_svc
		self.OpenIdConnectService = oidc_svc
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.RBACService = app.get_service("seacatauth.RBACService")
		self.ClientService = app.get_service("seacatauth.ClientService")
		self.ApiKeyService = app.get_service("seacatauth.ApiKeyService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_post("/openidconnect/introspect", self.introspect)
		web_app.router.add_post("/nginx/introspect/openidconnect", self.introspect_nginx)


	@asab.web.auth.noauth
	@asab.web.tenant.allow_no_tenant
	async def introspect(self, request):
		"""
		OAuth 2.0 Access Token Introspection Endpoint

		RFC7662 chapter 2

		POST /introspect HTTP/1.1
		Accept: application/json
		Content-Type: application/x-www-form-urlencoded

		token=2YotnFZFEjr1zCsicMWpAA&token_type_hint=access_token
		"""

		data = await request.text()
		qs_data = dict(urllib.parse.parse_qsl(data))

		if qs_data.get('token_type_hint', 'access_token') != 'access_token':
			raise RuntimeError("Token type is not 'access_token' but '{}'".format(
				qs_data.get('token_type_hint', '<not provided>'))
			)

		token = qs_data.get('token')
		if token is None:
			raise KeyError("Token not found")

		# TODO: Implement a token validation

		response = {
			"active": True,
		}
		return asab.web.rest.json_response(request, response)


	async def _authenticate_request(self, request):
		"""
		Authenticate request using access token or API key from Authorization header or Sec-WebSocket-Protocol header.

		Args:
			request (aiohttp.web.Request): Incoming request.

		Returns:
			session (Session|None): Authenticated session or None if authentication failed.
		"""
		token = get_token_from_authorization_header(request)
		if token is None:
			token = get_access_token_value_from_websocket(request)
		if token is None:
			L.log(asab.LOG_NOTICE, "Access token not found in 'Authorization' nor 'Sec-WebSocket-Protocol' header")
			return None

		token_type, token_value = token
		if token_type == "Bearer":
			try:
				session = await self.OpenIdConnectService.get_session_by_access_token(token_value)
			except exceptions.SessionNotFoundError as e:
				L.log(asab.LOG_NOTICE, "Access token matched no session: {}".format(e), struct_data={
					"token_fingerprint": fingerprint(token_value)})
				return None

		elif token_type == self.ApiKeyService.TOKEN_TYPE:
			try:
				session = await self.ApiKeyService.get_session_by_api_key(token_value)
			except exceptions.SessionNotFoundError as e:
				L.log(asab.LOG_NOTICE, "API key matched no session: {}".format(e), struct_data={
					"token_fingerprint": fingerprint(token_value)})
				return None

		else:
			L.error("Unsupported token type: {}".format(token_type))
			return None

		# Validate client if requested
		client = {}
		client_id = request.query.get("client_id")
		if client_id is not None:
			try:
				client = await self.ClientService.get_client(client_id)
			except KeyError:
				L.error("Client not found.", struct_data={"client_id": client_id})
				return None

			if session.OAuth2.ClientId != client_id:
				L.error("Client mismatch.", struct_data={
					"sid": session.SessionId,
					"request_client_id": client_id,
					"session_client_id": session.OAuth2.ClientId
				})
				return None

		# Validate authentication time if requested
		max_age = client.get("default_max_age") or None
		if "max_age" in request.query:
			max_age = asab.utils.convert_to_seconds(request.query["max_age"])
		if max_age is not None:
			if not session.Authentication.AuthnTime:
				L.error("Session has no authentication age.", struct_data={"sid": session.SessionId})
				return None

			authn_age = (datetime.datetime.now(datetime.UTC) - session.Authentication.AuthnTime).total_seconds()
			if authn_age > max_age:
				L.log(asab.LOG_NOTICE, "Maximum authentication age exceeded.", struct_data={
					"sid": session.SessionId,
					"client_id": client_id,
					"max_authn_age": max_age,
					"authn_age": authn_age,
				})
				return None

		return session


	@asab.web.auth.noauth
	@asab.web.tenant.allow_no_tenant
	async def introspect_nginx(self, request):
		"""
		Access token introspection

		Non-standard version of RFC7662 chapter 2.Introspection Endpoint that is usable with Nginx auth_request module.

		Based on:
		https://www.nginx.com/blog/validating-oauth-2-0-access-tokens-nginx/
		http://nginx.org/en/docs/http/ngx_http_auth_request_module.html

		If the request returns a 2xx response code, the access is allowed.
		If it returns 401 or 403, the access is denied with the corresponding error code.
		Any other response code returned by the subrequest is considered an error.

		For the 401 error, the client also receives the “WWW-Authenticate” header from the request response.
		e.g:
		WWW-Authenticate: Bearer realm="example" error="invalid_token" error_description="The access token expired"
		WWW-Authenticate: Bearer realm="example"

		# Nginx configuration

		http {
			...

			proxy_cache_path on keys_zone=token_responses:1m max_size=2m;
			...
			server {
				location / {
					auth_request /_oauth2_token_introspection;
					...
				}

				location = /_oauth2_token_introspection {
					internal;
					proxy_method          POST;
					proxy_set_body        "$http_authorization";
					proxy_pass            http://localhost:8900/nginx/introspect/openidconnect?client_id=my-app;

					proxy_cache           token_responses;     # Enable caching
					proxy_cache_key       $http_authorization; # Cache for each access token
					proxy_cache_lock      on;                  # Duplicate tokens must wait
					proxy_cache_valid     200 10s;             # How long to use each response
					proxy_ignore_headers  Cache-Control Expires Set-Cookie;
				}

		}

		---
		tags: ["Nginx"]
		"""

		session = await self._authenticate_request(request)

		if session is not None:
			try:
				response = await nginx_introspection(request, session, self.OpenIdConnectService.App)
			except Exception as e:
				L.exception("Introspection failed: {}".format(e))
				response = aiohttp.web.HTTPUnauthorized()
		else:
			response = aiohttp.web.HTTPUnauthorized()

		if response.status_code != 200:
			response.headers["WWW-Authenticate"] = 'Bearer realm="{}"'.format(self.OpenIdConnectService.BearerRealm)
			return response

		return response
