import aiohttp.web
import asab
import logging
from .generic import SessionContext

from . import exceptions
from .generic import get_bearer_token_value


L = logging.getLogger(__name__)


def app_middleware_factory(app):

	@aiohttp.web.middleware
	async def app_middleware(request, handler):
		"""
		Add the application object to the request.
		"""
		request.App = app
		return await handler(request)

	return app_middleware


def private_auth_middleware_factory(app):
	oidc_service = app.get_service("seacatauth.OpenIdConnectService")
	require_authentication = asab.Config.getboolean("seacat:api", "require_authentication")
	_allow_access_token_auth = asab.Config.getboolean("seacat:api", "_allow_access_token_auth")
	asab_api_required_bearer_token = asab.Config.get("asab:api:auth", "bearer", fallback=None)

	rbac_svc = app.get_service("seacatauth.RBACService")

	@aiohttp.web.middleware
	async def private_auth_middleware(request, handler):
		"""
		Authenticate and authorize all incoming requests.
		Raise HTTP 401 if authentication or authorization fails.

		ASAB api endpoints can be accessed with simple authorization using configured bearer token requesting the Private WebContainer directly.

		SeaCat configuration example:
		[asab:api:auth]
		bearer=xtA4J9c6KK3g_Y0VplS_Rz4xmoVoU1QWrwz9CHz2p3aTpHzOkr0yp3xhcbkJK-Z0
		"""
		request.Session = None

		if request.path.startswith("/nginx/"):
			# NGINX introspection endpoints handle authentication on their own
			return await handler(request)

		elif request.path.startswith("/.well-known/"):
			# Well-known endpoints use no authentication
			return await handler(request)

		token_value = get_bearer_token_value(request)
		if token_value is not None:
			try:
				request.Session = await oidc_service.get_session_by_id_token(token_value)
			except ValueError:
				# If the token cannot be parsed as ID token, it may be an Access token
				if _allow_access_token_auth:
					try:
						request.Session = await oidc_service.get_session_by_access_token(token_value)
					except exceptions.SessionNotFoundError:
						request.Session = None
				else:
					L.info("Invalid Bearer token")

		def has_resource_access(tenant: str, resource: str) -> bool:
			if request.Session is None:
				return False
			return rbac_svc.has_resource_access(request.Session.Authorization.Authz, tenant, [resource])

		request.has_resource_access = has_resource_access
		request.is_superuser = rbac_svc.is_superuser(request.Session.Authorization.Authz) \
			if request.Session is not None else False
		request.can_access_all_tenants = rbac_svc.can_access_all_tenants(request.Session.Authorization.Authz) \
			if request.Session is not None else False

		SessionContext.set(request.Session)

		if require_authentication is False:
			return await handler(request)

		# All API endpoints are considered non-public and have to pass authn/authz
		if request.Session is not None and request.Session.Authorization.Authz is not None:
			return await handler(request)

		# ASAB API can be protected with a pre-configured bearer token
		if (request.path.startswith("/asab/v1") or request.path in ("/doc", "/oauth2-redirect.html")) \
			and request.method == "GET":
			if asab_api_required_bearer_token:
				if request.headers.get("Authorization") == "Bearer {}".format(asab_api_required_bearer_token):
					return await handler(request)
				else:
					L.log(asab.LOG_NOTICE, "Invalid bearer token for ASAB API access")
					return aiohttp.web.HTTPUnauthorized()
			else:
				return await handler(request)

		return aiohttp.web.HTTPUnauthorized()

	return private_auth_middleware


def public_auth_middleware_factory(app):
	cookie_service = app.get_service("seacatauth.CookieService")
	oidc_service = app.get_service("seacatauth.OpenIdConnectService")
	_allow_access_token_auth = asab.Config.getboolean("seacat:api", "_allow_access_token_auth")

	@aiohttp.web.middleware
	async def public_auth_middleware(request, handler):
		"""
		Try to authenticate before accessing public endpoints.
		"""
		request.Session = None

		# If Bearer token exists, authorize using Bearer token and ignore cookie
		token_value = get_bearer_token_value(request)
		if token_value is not None:
			try:
				request.Session = await oidc_service.get_session_by_id_token(token_value)
			except ValueError:
				# If the token cannot be parsed as ID token, it may be an Access token
				# OIDC endpoints allow authorization via Access token
				if request.path.startswith("/openidconnect/"):
					try:
						request.Session = await oidc_service.get_session_by_access_token(token_value)
					except exceptions.SessionNotFoundError:
						request.Session = None
					# Allow authorization via Access token on all public endpoints if enabled in config
				elif _allow_access_token_auth:
					try:
						request.Session = await oidc_service.get_session_by_access_token(token_value)
					except exceptions.SessionNotFoundError:
						request.Session = None
				else:
					L.log(asab.LOG_NOTICE, "Invalid bearer token")
					return aiohttp.web.HTTPUnauthorized()
		else:
			# No Bearer token exists, authorize using cookie
			try:
				request.Session = await cookie_service.get_session_by_request_cookie(request)
			except exceptions.NoCookieError:
				L.info("No root cookie found in request")
				request.Session = None
			except exceptions.SessionNotFoundError:
				L.log(asab.LOG_NOTICE, "Cannot locate session by root cookie: Session missing or expired")
				request.Session = None

		SessionContext.set(request.Session)
		return await handler(request)

	return public_auth_middleware
