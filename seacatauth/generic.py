import random
import logging
import urllib.parse
import aiohttp.web
import asab

from .session import SessionAdapter

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


async def add_to_header(headers, attributes_to_add, session, requested_tenant=None):
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
		headers["X-Credentials"] = session.Credentials.Id
		if session.Credentials.Username is not None:
			headers["X-Username"] = session.Credentials.Username

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
	session: SessionAdapter,
	app: asab.Application
):
	"""
	Helper function for different types of nginx introspection (Cookie, OAuth token, Basic auth).

	Authenticates the introspection request and responds with 200 if successful or with 401 if not.
	Optionally checks for resources. Missing resource access results in 403 response.
	Optionally adds session attributes (username, tenants etc.) to X-headers.
	"""

	# TODO: Optionally, validate the request URI (in request.headers["X-Request-Uri"])

	session_service = app.get_service("seacatauth.SessionService")
	rbac_service = app.get_service("seacatauth.RBACService")
	oidc_service = app.get_service("seacatauth.OpenIdConnectService")
	cookie_service = app.get_service("seacatauth.CookieService")

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
	# (Do not extend algorithmic sessions)
	if not session.is_algorithmic():
		session = await session_service.touch(session)

	id_token = await oidc_service.build_id_token(session)

	# Set the authorization header
	headers = {
		aiohttp.hdrs.AUTHORIZATION: "Bearer {}".format(id_token)
	}

	# Delete SeaCat cookie from header unless "keepcookie" param is passed in query
	cookie_string = request.headers.get(aiohttp.hdrs.COOKIE, "")
	if request.query.get("keepcookie") is None:
		cookie_string = cookie_service.CookiePattern.sub("", cookie_string)
	headers[aiohttp.hdrs.COOKIE] = cookie_string

	# Add headers
	headers = await add_to_header(
		headers=headers,
		attributes_to_add=attributes_to_add,
		session=session,
		requested_tenant=requested_tenant
	)

	response = aiohttp.web.HTTPOk(headers=headers)
	return response


def urlparse(url: str):
	"""
	Parse the URL into a dictionary.

	Convenience wrapper around urllib.parse.urlparse().
	"""
	return urllib.parse.urlparse(url)._asdict()


def urlunparse(
	*,
	scheme: str = "",
	netloc: str = "",
	path: str = "",
	params: str = "",
	query: str = "",
	fragment: str = ""
):
	"""
	Build URL from individual components.

	Convenience wrapper around urllib.parse.urlunparse().

	Example usage:
	```python
	parsed = parse_url("http://local.test?option=true")
	parsed["path"] = "/some/subpath"
	url = unparse_url(**parsed)
	```
	"""
	return urllib.parse.urlunparse((scheme, netloc, path, params, query, fragment))


def add_params_to_url_query(url, **params):
	parsed = urlparse(url)
	query = urllib.parse.parse_qs(parsed["query"])
	query.update(params)
	parsed["query"] = urllib.parse.urlencode(query)
	return urlunparse(**parsed)


def generate_ergonomic_token(length: int):
	'''
	This function generates random string that is "ergonomic".
	This means that it contains only the letters and numbers that are unlikely to be misread by people.
	'''
	assert (length >= 1)
	return ''.join(random.choice(ergonomic_characters) for _ in range(length))


# These are characters that are safe (prevents confusion with other characters)
ergonomic_characters = "23456789abcdefghjkmnpqrstuvxyz"
