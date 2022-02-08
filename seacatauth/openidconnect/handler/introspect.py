import urllib
import logging

import aiohttp
import aiohttp.web

import asab
import asab.web.rest

from ...generic import add_to_header

#

L = logging.getLogger(__name__)

#


class TokenIntrospectionHandler(object):
	'''
	OAuth 2.0 Token Introspection
	https://tools.ietf.org/html/rfc7662
	'''

	def __init__(self, app, oidc_svc, credentials_svc):
		self.CredentialsService = credentials_svc
		self.OpenIdConnectService = oidc_svc
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.RBACService = app.get_service("seacatauth.RBACService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_post('/openidconnect/introspect', self.introspect)
		web_app.router.add_post('/openidconnect/introspect/nginx', self.introspect_nginx)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_post('/openidconnect/introspect', self.introspect)
		web_app_public.router.add_post('/openidconnect/introspect/nginx', self.introspect_nginx)


	async def introspect(self, request):
		"""
		RFC7662 chapter 2.Introspection Endpoint

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


	async def introspect_nginx(self, request):
		"""
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
					proxy_set_header      X-Request-URI "$request_uri";
					proxy_pass            http://localhost:8080/openidconnect/introspect/nginx;

					proxy_cache           token_responses;     # Enable caching
					proxy_cache_key       $http_authorization; # Cache for each access token
					proxy_cache_lock      on;                  # Duplicate tokens must wait
					proxy_cache_valid     200 10s;             # How long to use each response
					proxy_ignore_headers  Cache-Control Expires Set-Cookie;
				}

		}
		"""
		attributes_to_add = request.query.getall("add", [])
		attributes_to_verify = request.query.getall("verify", [])
		requested_resources = set(request.query.getall("resource", []))

		headers = {}

		# Authorize request
		# Use custom authorization since the auth bytes must be read from the request body, not the header
		authorization_bytes = await request.read()
		session = await self.OpenIdConnectService.get_session_from_bearer_token(authorization_bytes.decode("ascii"))
		if session is None:
			headers["WWW-Authenticate"] = 'Bearer realm="{}"'.format(self.OpenIdConnectService.BearerRealm)
			return aiohttp.web.HTTPUnauthorized(headers=headers)

		# TODO: check if user is in a "limited" session (for setting up 2nd factor only)
		#   if so: fail

		requested_tenant = None
		if "tenant" in attributes_to_verify:
			requested_tenant = request.headers.get("X-Tenant")
			requested_resources.add("tenant:access")

		if len(requested_resources) > 0:
			if self.RBACService.has_resource_access(session.Authz, requested_tenant, requested_resources) != "OK":
				L.warning("Credentials not authorized for tenant or resource.", struct_data={
					"cid": session.CredentialsId,
					"tenant": requested_tenant,
					"resources": " ".join(requested_resources),
				})
				headers["WWW-Authenticate"] = 'Bearer realm="{}"'.format(self.OpenIdConnectService.BearerRealm)
				return aiohttp.web.HTTPForbidden(headers=headers)

		# Extend session expiration
		await self.SessionService.touch(session)

		# add headers
		headers = await add_to_header(
			headers=headers,
			what=attributes_to_add,
			session=session,
			credentials_service=self.CredentialsService,
			requested_tenant=requested_tenant
		)

		return aiohttp.web.HTTPOk(headers=headers)
