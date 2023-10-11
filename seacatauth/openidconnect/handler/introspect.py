import logging
import aiohttp.web

import asab
import asab.web.rest
import asab.exceptions

from ...generic import nginx_introspection, get_bearer_token_value

#

L = logging.getLogger(__name__)

#


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

		web_app = app.WebContainer.WebApp
		web_app.router.add_post(self.OpenIdConnectService.IntrospectionPath, self.introspect)
		web_app.router.add_post(self.OpenIdConnectService.NginxIntrospectionPath, self.introspect_nginx)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_post(self.OpenIdConnectService.IntrospectionPath, self.introspect)
		web_app_public.router.add_post(self.OpenIdConnectService.NginxIntrospectionPath, self.introspect_nginx)


	async def introspect(self, request):
		"""
		OAuth 2.0 Access Token Introspection Endpoint

		RFC7662 chapter 2

		POST /introspect HTTP/1.1
		Accept: application/json
		Content-Type: application/x-www-form-urlencoded

		token=2YotnFZFEjr1zCsicMWpAA&token_type_hint=access_token

		---
		requestBody:
			required: true
			content:
				application/x-www-form-urlencoded:
					schema:
						type: object
						properties:
							client_id:
								type: string
								description: ID of the client requesting the introspection.
							token:
								type: string
								description: The OAuth 2.0 token to introspect.
							token_type_hint:
								type: string
								enum: [access_token, refresh_token]
								description: The type of token being introspected (optional).
						required:
						- token
						- client_id
		"""
		params = await request.post()

		client_id = params.get("client_id")
		if not client_id:
			L.error("Missing 'client_id' parameter.")
			return asab.web.rest.json_response(request, {"active": False})
		try:
			await self.OpenIdConnectService.ClientService.get(client_id)
		except KeyError:
			L.error("Client not found.", struct_data={"client_id": client_id})
			return asab.web.rest.json_response(request, {"active": False})

		# TODO: To prevent token scanning attacks, the endpoint MUST also require
		#    some form of authorization to access this endpoint, such as client
		#    authentication as described in OAuth 2.0 [RFC6749] or a separate
		#    OAuth 2.0 access token such as the bearer token described in OAuth
		#    2.0 Bearer Token Usage [RFC6750].

		token = params.get("token")
		if not token:
			L.error("Missing 'token' parameter.")
			return asab.web.rest.json_response(request, {"active": False})

		# If the server is unable to locate the token using the given hint, it MUST extend its search across
		# all of its supported token types.
		token_type_hint = params.get("token_type_hint", "access_token")
		if token_type_hint != "access_token":
			# No other types are supported at the moment.
			L.error("Unsupported token_type_hint {!r}.".format(token_type_hint))
			return asab.web.rest.json_response(request, {"active": False})

		session = await self.OpenIdConnectService.get_session_by_access_token(token)
		if session is None:
			L.log(asab.LOG_NOTICE, "Access token matched no active session.")
			return asab.web.rest.json_response(request, {"active": False})

		user_info = await self.OpenIdConnectService.build_userinfo(session)
		response_data = {
			# REQUIRED
			"active": True,
			# OPTIONAL
			"token_type": "access_token",
			"client_id": user_info.get("azp"),
			"exp": user_info.get("exp"),
			"iat": user_info.get("iat"),
			"sub": user_info.get("sub"),
			"aud": user_info.get("aud"),
			"iss": user_info.get("iss"),
		}
		if "preferred_username" in user_info:
			response_data["username"] = user_info["preferred_username"]

		# TODO: Verify that the token is  client_id is included in the aud claim

		return asab.web.rest.json_response(request, response_data)


	async def _authenticate_request(self, request):
		token_value = get_bearer_token_value(request)
		if token_value is None:
			L.log(asab.LOG_NOTICE, "No Bearer token in Authorization header.")
			return None
		session = await self.OpenIdConnectService.get_session_by_access_token(token_value)
		if session is None:
			L.log(asab.LOG_NOTICE, "Access token matched no session.")
		return session


	async def introspect_nginx(self, request):
		"""
		Access token introspection for Nginx

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
					proxy_pass            http://localhost:8080/openidconnect/introspect/nginx;

					proxy_cache           token_responses;     # Enable caching
					proxy_cache_key       $http_authorization; # Cache for each access token
					proxy_cache_lock      on;                  # Duplicate tokens must wait
					proxy_cache_valid     200 10s;             # How long to use each response
					proxy_ignore_headers  Cache-Control Expires Set-Cookie;
				}

		}
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
