import base64
import logging

import aiohttp.web

from ..generic import add_to_header
from ..session import SessionAdapter

#

L = logging.getLogger(__name__)

#


class M2MIntrospectHandler(object):

	def __init__(self, app, authn_svc, session_svc, credentials_service, rbac_service):
		self.AuthnService = authn_svc
		self.SessionService = session_svc
		self.CredentialsService = credentials_service
		self.RBACService = rbac_service

		self.BasicRealm = "asab"  # TODO: Configurable

		web_app = app.WebContainer.WebApp
		web_app.router.add_post('/m2m/nginx', self.nginx)

		# Public aliases
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_post('/m2m/nginx', self.nginx)


	async def nginx(self, request):
		"""
		Authenticate M2M call

		If introspection is successful, Basic auth header is replaced with Bearer token.

		Example Nginx setup:
		```nginx
		# Protected location
		location /protected-api {
			auth_request /_m2m_introspect;
			auth_request_set      $authorization $upstream_http_authorization;
			proxy_set_header      Authorization $authorization;
			proxy_pass            http://protected-api:8080
		}

		# Introspection endpoint
		location = /_m2m_introspect {
			internal;
			proxy_method          POST;
			proxy_set_header      X-Request-URI "$request_uri";
			proxy_set_body        "$http_authorization";
			proxy_pass            http://seacat-auth-svc:8081/m2m/nginx;
		}
		```
		"""
		# TODO: API key auth
		# TODO: Certificate auth
		query = request.query
		verify = query.get("verify", "")
		what = query.getall("add", [])

		# Get credentials from request
		authorization_bytes = await request.read()
		requested_tenant = request.headers.get("X-Tenant")

		headers = {
			"WWW-Authenticate": 'Basic realm="{}"'.format(self.BasicRealm)
		}

		# Get Basic auth credentials
		if authorization_bytes.startswith(b'Basic '):
			username_password = base64.urlsafe_b64decode(authorization_bytes[len(b'Basic '):]).decode("ascii")
			username, password = username_password.split(":", 1)
		else:
			L.warning("Basic auth token not provided in request", struct_data={"headers": dict(request.headers)})
			return aiohttp.web.HTTPUnauthorized(headers=headers)

		# Locate credentials
		credentials_id = await self.CredentialsService.locate(username, stop_at_first=True)
		provider = self.CredentialsService.get_provider(credentials_id)

		# Check if machine credentials
		if provider.Type != "m2m":
			L.warning("Authn method not available for given credentials", struct_data={"headers": dict(request.headers)})
			return aiohttp.web.HTTPUnauthorized(headers=headers)

		# Authenticate request
		authenticated = await provider.authenticate(
			credentials_id,
			{"password": password}
		)
		if not authenticated:
			return aiohttp.web.HTTPUnauthorized(headers=headers)

		# Find session object
		try:
			session = await self.SessionService.get_by(SessionAdapter.FNCredentialsId, credentials_id)
		except KeyError:
			session = None

		if session is None:
			# No session for given credentials exists; create a new one
			access_ips = [request.remote]
			ff = request.headers.get("X-Forwarded-For")
			if ff is not None:
				access_ips.extend(ff.split(", "))
			session = await self.AuthnService.m2m_login(
				credentials_id,
				login_descriptor=None,
				session_expiration=None,  # TODO: Short expiration
				from_info=access_ips
			)
			if session is None:
				return aiohttp.web.HTTPUnauthorized(headers=headers)
		else:
			# Session exists for given credentials
			# Extend session expiration
			await self.SessionService.touch(session)

		# Check tenant access
		if "tenant" in verify:
			if self.RBACService.has_resource_access(
				request.Session.Authz,
				requested_tenant,
				["authz:tenant:admin"]
			) != "OK":
				L.warning(
					"Credentials not authorized for tenant.",
					struct_data={
						"cid": credentials_id,
						"tenant": requested_tenant
					}
				)
				return aiohttp.web.HTTPUnauthorized(headers=headers)

		# Replace Basic auth token with Bearer token in Authorization header
		headers[aiohttp.hdrs.AUTHORIZATION] = "Bearer {}".format(session.OAuth2['access_token'])

		# Add HTTP headers
		headers = await add_to_header(
			headers=headers,
			what=what,
			session=session,
			credentials_service=self.CredentialsService,
			requested_tenant=requested_tenant
		)

		return aiohttp.web.HTTPOk(headers=headers)
