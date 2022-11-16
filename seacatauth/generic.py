import random
import logging
import typing

import aiohttp.web
import asab

#

L = logging.getLogger(__name__)

#


def get_bearer_token_value(request):
	bearer_prefix = "Bearer "
	auth_header = request.headers.get(aiohttp.hdrs.AUTHORIZATION, None)
	if auth_header is None:
		L.info("Request has no Authorization header")
		return None
	if auth_header.startswith(bearer_prefix):
		return auth_header[len(bearer_prefix):]
	else:
		L.info("No Bearer token in Authorization header")
		return None


async def add_to_header(headers, attributes_to_add, session, credentials_service, requested_tenant=None):
	"""
	Prepare a common header with:
	* X-Credentials: htpasswd:id:foobar
	* X-Username: foobar
	* X-Tenants: tenant1 tenant2 tenant3
	* X-Roles: role1 role2 role3
	* X-Resources: resource1 resource2 resource3
	"""

	# obtain username to append add in headers
	if "credentials" in attributes_to_add:
		credentials = await credentials_service.get(session.Credentials.Id)
		headers["X-Credentials"] = credentials["_id"]
		v = credentials.get("username")
		if v is not None:
			headers["X-Username"] = v

	# Obtain assigned tenants from session object
	if "tenants" in attributes_to_add:
		tenants = [tenant for tenant in session.Authorization.Authz.keys() if tenant != "*"]
		if len(tenants) > 0:
			headers["X-Tenants"] = " ".join(tenants)

	# Obtain assigned resources from session object
	if "resources" in attributes_to_add:
		if requested_tenant is None:
			resources = session.Authorization.Authz["*"]
		else:
			resources = session.Authorization.Authz[requested_tenant]
		headers["X-Resources"] = " ".join(resources)

	# Obtain login factors from session object
	if "factors" in attributes_to_add:
		if session.Authentication.LoginDescriptor is not None:
			factors = [
				factor["id"]
				for factor
				in session.Authentication.LoginDescriptor["factors"]
			]
			headers["X-Login-Factors"] = " ".join(factors)

	# Obtain login descriptor IDs from session object
	if "ldid" in attributes_to_add:
		if session.Authentication.LoginDescriptor is not None:
			headers["X-Login-Descriptor"] = session.Authentication.LoginDescriptor["id"]

	return headers


async def nginx_introspection(
	request: aiohttp.web.Request,
	authenticate: typing.Callable,
	app: asab.Application
):
	"""
	Helper function for different types of nginx introspection (Cookie, OAuth token, Basic auth).

	Authenticates the introspection request and responds with 200 if successful or with 401 if not.
	Optionally checks for resources. Missing resource access results in 403 response.
	Optionally adds session attributes (username, tenants etc.) to X-headers.
	"""
	credentials_service = app.get_service("seacatauth.CredentialsService")
	session_service = app.get_service("seacatauth.SessionService")
	rbac_service = app.get_service("seacatauth.RBACService")
	oidc_service = app.get_service("seacatauth.OpenIdConnectService")
	authn_service = app.get_service("seacatauth.AuthenticationService")

	anonymous_cid = request.query.get("anonymous")

	# Authenticate request, get session
	session = await authenticate(request)
	set_cookie = False
	if session is not None:
		# Allow anonymous access only if it is allowed by the introspect parameters
		if "authn:anonymous" in session.Authorization.Authz.get("*", {}):
			raise aiohttp.web.HTTPUnauthorized()
	else:
		if anonymous_cid is not None:
			# Create a new root session with anonymous_cid and a cookie
			# Set the cookie
			from_info = [request.remote]
			forwarded_for = request.headers.get("X-Forwarded-For")
			if forwarded_for is not None:
				from_info.extend(forwarded_for.split(", "))
			session = await authn_service.create_anonymous_session(anonymous_cid, from_info=from_info)
			set_cookie = True
		else:
			raise aiohttp.web.HTTPUnauthorized()

	attributes_to_add = request.query.getall("add", [])
	attributes_to_verify = request.query.getall("verify", [])
	requested_resources = set(request.query.getall("resource", []))

	requested_tenant = None
	if "tenant" in attributes_to_verify:
		raise NotImplementedError("Tenant check not implemented in introspection")

	if len(requested_resources) > 0:
		if not rbac_service.has_resource_access(session.Authorization.Authz, requested_tenant, requested_resources):
			L.warning("Credentials not authorized for tenant or resource.", struct_data={
				"cid": session.Credentials.Id,
				"tenant": requested_tenant,
				"resources": " ".join(requested_resources),
			})
			return aiohttp.web.HTTPForbidden()

	# Extend session expiration
	session = await session_service.touch(session)

	# TODO: Tenant-specific token (session)
	id_token = await oidc_service.build_id_token(session)

	# Set the authorization header
	headers = {
		aiohttp.hdrs.AUTHORIZATION: "Bearer {}".format(id_token)
	}

	# Add headers
	headers = await add_to_header(
		headers=headers,
		attributes_to_add=attributes_to_add,
		session=session,
		credentials_service=credentials_service,
		requested_tenant=requested_tenant
	)

	response = aiohttp.web.HTTPOk(headers=headers)
	if set_cookie:
		response.set_cookie(
			"SeaCatSCI",
			session.Cookie.Id,
			httponly=True,
			domain=".local.loc",  # TODO!!!
			secure=True
		)
	return response


def generate_ergonomic_token(length: int):
	'''
	This function generates random string that is "ergonomic".
	This means that it contains only the letters and numbers that are unlikely to be misread by people.
	'''
	assert (length >= 1)
	return ''.join(random.choice(ergonomic_characters) for _ in range(length))


# These are characters that are safe (prevents confusion with other characters)
ergonomic_characters = "23456789abcdefghjkmnpqrstuvxyz"
