import base64
import binascii
import logging
import aiohttp.web
import asab

from ..generic import nginx_introspection
from ..session import SessionAdapter

#

L = logging.getLogger(__name__)

#


class M2MIntrospectHandler(object):

	def __init__(self, app, authn_svc, session_svc, credentials_service, rbac_service):
		self.App = app
		self.AuthnService = authn_svc
		self.SessionService = session_svc
		self.CredentialsService = credentials_service
		self.RBACService = rbac_service

		self.BasicRealm = "asab"  # TODO: Configurable

		web_app = app.WebContainer.WebApp
		web_app.router.add_post("/nginx/introspect/m2m", self.nginx)

		# TODO: Insecure, back-compat only - remove after 2024-03-31
		if asab.Config.getboolean("seacatauth:introspection", "_enable_insecure_legacy_endpoints", fallback=False):
			web_app_public = app.PublicWebContainer.WebApp
			web_app_public.router.add_post("/m2m/nginx", self.nginx)


	async def _authenticate_request(self, request, client_id):
		# Get credentials from request
		authorization_bytes = await request.read()

		# Get Basic auth credentials
		if not authorization_bytes.startswith(b'Basic '):
			L.log(asab.LOG_NOTICE, "Basic auth token not provided in request")
			return None

		try:
			username_password = base64.urlsafe_b64decode(authorization_bytes[len(b'Basic '):]).decode("ascii")
		except binascii.Error:
			L.log(asab.LOG_NOTICE, "Basic auth token must be base64-encoded")
			return None

		try:
			username, password = username_password.split(":", 1)
		except ValueError:
			L.log(asab.LOG_NOTICE, "Basic auth token must match the 'username:password' format")
			return None

		# Locate credentials
		credentials_id = await self.CredentialsService.locate(username, stop_at_first=True)
		if credentials_id is None:
			L.log(asab.LOG_NOTICE, "Credentials not found", struct_data={"username": username})
			return None
		provider = self.CredentialsService.get_provider(credentials_id)

		# Check if machine credentials
		if provider.Type != "m2m":
			L.log(
				asab.LOG_NOTICE,
				"Authentication method only available for machine credentials",
				struct_data={"cid": credentials_id})
			return None

		# Authenticate request
		authenticated = await provider.authenticate(
			credentials_id,
			{"password": password}
		)
		if not authenticated:
			L.log(asab.LOG_NOTICE, "Basic authentication failed", struct_data={"cid": credentials_id})
			return None

		# Find session object
		try:
			session = await self.SessionService.get_by(SessionAdapter.FN.Credentials.Id, credentials_id)
		except KeyError:
			session = None

		if session is None:
			# No session for given credentials exists; create a new one
			access_ips = [request.remote]
			ff = request.headers.get("X-Forwarded-For")
			if ff is not None:
				access_ips.extend(ff.split(", "))
			login_descriptor = {
				"id": "!m2m",
				"factors": [{"type": "!m2m-basic-auth"}]
			}
			session = await self.AuthnService.create_m2m_session(
				credentials_id,
				login_descriptor=login_descriptor,
				session_expiration=None,  # TODO: Short expiration
				from_info=access_ips
			)
		if session is None:
			L.warning("M2M login failed", struct_data={
				"cid": credentials_id
			})
			return None

		return session


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
			proxy_set_body        "$http_authorization";
			proxy_pass            http://seacat-auth-svc:8081/m2m/nginx;
		}
		```
		"""
		# TODO: API key auth
		# TODO: Certificate auth
		# TODO: Require client_id in query string
		client_id = request.query.get("client_id")
		session = await self._authenticate_request(request, client_id)
		if session is not None:
			try:
				response = await nginx_introspection(request, session, self.App)
			except Exception as e:
				L.exception("Introspection failed: {}".format(e))
				response = aiohttp.web.HTTPUnauthorized()
		else:
			response = aiohttp.web.HTTPUnauthorized()

		if response.status_code != 200:
			response.headers["WWW-Authenticate"] = 'Basic realm="{}"'.format(self.BasicRealm)
			return response

		return response
