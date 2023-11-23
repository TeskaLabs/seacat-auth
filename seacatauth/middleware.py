import aiohttp.web
import asab
import logging

from . import exceptions
from .generic import get_bearer_token_value

#

L = logging.getLogger(__name__)

#


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
	api_resource_id = asab.Config.get("seacat:api", "authorization_resource")
	asab_api_required_bearer_token = asab.Config.get("asab:api:auth", "bearer", fallback=None)

	rbac_svc = app.get_service("seacatauth.RBACService")

	@aiohttp.web.middleware
	async def private_auth_middleware(request, handler):
		"""
		Authenticate and authorize incoming requests.
		Raise HTTP 401 if authentication or authorization fails.

		ASAB api endpoints can be accessed with simple authorization using configured bearer token requesting the Private WebContainer directly.

		SeaCat configuration example:
		[asab:api:auth]
		bearer=xtA4J9c6KK3g_Y0VplS_Rz4xmoVoU1QWrwz9CHz2p3aTpHzOkr0yp3xhcbkJK-Z0
		"""

		# Nginx introspection
		if request.path.startswith("/nginx/"):
			return await handler(request)

		# OpenID API
		if request.path.startswith("/openidconnect/"):
			return await handler(request)

		# Well-known locations
		if request.path.startswith("/.well-known/"):
			return await handler(request)

		# Endpoints that handle unauthenticated users: login, registration etc.
		if request.path.startswith("/public/"):
			return await handler(request)

		# OpenAPI with Swagger UI
		if request.path in ("/doc", "/oauth2-redirect.html", "/asab/v1/openapi"):
			return await handler(request)

		# ASAB API can be protected with a pre-configured static bearer token
		if asab_api_required_bearer_token and request.path.startswith("/asab/v1") and request.method == "GET":
			if request.headers.get("Authorization") == "Bearer {}".format(asab_api_required_bearer_token):
				return await handler(request)
			else:
				L.log(asab.LOG_NOTICE, "Invalid bearer token for ASAB API access")
				return aiohttp.web.HTTPUnauthorized()

		# !!! Anything else must authenticate with ID token !!!

		# Authenticate
		request.Session = None
		token_value = get_bearer_token_value(request)
		if token_value is not None:
			try:
				request.Session = await oidc_service.get_session_by_id_token(token_value)
			except ValueError:
				L.info("Invalid Bearer token")

		# Deny unauthenticated or anonymous requests
		if request.Session is None:
			L.log(asab.LOG_NOTICE, "Authentication required")
			return aiohttp.web.HTTPUnauthorized()
		elif request.Session.Authentication.IsAnonymous:
			L.log(asab.LOG_NOTICE, "Anonymous access not allowed", struct_data={
				"cid": request.Session.Credentials.Id})
			return aiohttp.web.HTTPUnauthorized()

		# Add utility RBAC methods
		def has_resource_access(tenant: str, resource: str) -> bool:
			if request.Session is None:
				return False
			return rbac_svc.has_resource_access(request.Session.Authorization.Authz, tenant, [resource])

		request.has_resource_access = has_resource_access
		request.is_superuser = rbac_svc.is_superuser(request.Session.Authorization.Authz) \
			if request.Session is not None else False
		request.can_access_all_tenants = rbac_svc.can_access_all_tenants(request.Session.Authorization.Authz) \
			if request.Session is not None else False

		# Seacat Account API
		if request.path.startswith("/account/"):
			return await handler(request)

		# Seacat Admin API
		elif request.path.startswith("/admin/"):
			if api_resource_id == "DISABLED":
				return await handler(request)
			# Resource authorization is required: scan ALL THE RESOURCES
			#   for `authorization_resource` or "authz:superuser"
			authorized_resources = set(
				resource
				for resources in request.Session.Authorization.Authz.values()
				for resource in resources
			)
			# Check the session is authorized to access Seacat API
			if "authz:superuser" in authorized_resources or api_resource_id in authorized_resources:
				return await handler(request)
			else:
				L.log(asab.LOG_NOTICE, "Not authorized to access Seacat Admin API", struct_data={
					"resource_id": api_resource_id})
				return aiohttp.web.HTTPForbidden()

		# ASAB API
		elif request.path.startswith("/asab/v1") or request.path in ("/doc", "/oauth2-redirect.html"):
			return await handler(request)

		# There should be no other path
		L.error("Unexpected path: {}".format(request.path))
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
					request.Session = await oidc_service.get_session_by_access_token(token_value)
				# Allow authorization via Access token on all public endpoints if enabled in config
				elif _allow_access_token_auth:
					request.Session = await oidc_service.get_session_by_access_token(token_value)
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

		return await handler(request)

	return public_auth_middleware
