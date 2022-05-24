import random
import logging
import typing

import aiohttp.web
import asab

#

L = logging.getLogger(__name__)

#


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

	# Obtain assigned roles from session object
	if "roles" in attributes_to_add:
		# Add only global roles if no tenant was requested
		if requested_tenant is None:
			roles = session.Authorization.Authz["*"].keys()
		else:
			roles = session.Authorization.Authz[requested_tenant].keys()
		headers["X-Roles"] = " ".join(roles)

	# Obtain assigned resources from session object
	if "resources" in attributes_to_add:
		if requested_tenant is None:
			resources = session.Authorization.Authz["*"].values()
		else:
			resources = session.Authorization.Authz[requested_tenant].values()
		headers["X-Resources"] = " ".join(set(sum(resources, [])))

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
	credentials_service: asab.Service,
	session_service: asab.Service,
	rbac_service: asab.Service
):
	"""
	Helper function for different types of nginx introspection (Cookie, OAuth token, Basic auth).

	Authenticates the introspection request and responds with 200 if successful or with 401 if not.
	Optionally checks for resources. Missing resource access results in 403 response.
	Optionally adds session attributes (username, tenants etc.) to X-headers.
	"""

	# Authenticate request, get session
	session = await authenticate(request)
	if session is None:
		return aiohttp.web.HTTPUnauthorized()

	# TODO: Check if the session is "restricted" (for setting up 2nd factor only)
	#   if so: fail

	attributes_to_add = request.query.getall("add", [])
	attributes_to_verify = request.query.getall("verify", [])
	requested_resources = set(request.query.getall("resource", []))

	requested_tenant = None
	if "tenant" in attributes_to_verify:
		raise NotImplementedError("Tenant check not implemented in introspection")

	if len(requested_resources) > 0:
		if rbac_service.has_resource_access(session.Authorization.Authz, requested_tenant, requested_resources) != "OK":
			L.warning("Credentials not authorized for tenant or resource.", struct_data={
				"cid": session.Credentials.Id,
				"tenant": requested_tenant,
				"resources": " ".join(requested_resources),
			})
			return aiohttp.web.HTTPForbidden()

	# Extend session expiration
	await session_service.touch(session)

	# Set the authorization header
	headers = {
		aiohttp.hdrs.AUTHORIZATION: "Bearer {}".format(session.OAuth2.IDToken)
	}

	# Add headers
	headers = await add_to_header(
		headers=headers,
		attributes_to_add=attributes_to_add,
		session=session,
		credentials_service=credentials_service,
		requested_tenant=requested_tenant
	)

	return aiohttp.web.HTTPOk(headers=headers)


def generate_ergonomic_token(length: int):
	'''
	This function generates random string that is "ergonomic".
	This means that it contains only the letters and numbers that are unlikely to be misread by people.
	'''
	assert(length >= 1)
	return ''.join(random.choice(ergonomic_characters) for _ in range(length))


# These are characters that are safe (prevents confusion with other characters)
ergonomic_characters = "23456789abcdefghjkmnpqrstuvxyz"
