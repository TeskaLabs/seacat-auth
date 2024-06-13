import random
import logging
import re
import typing
import urllib.parse
import aiohttp.web
import asab
import bcrypt
import argon2

from .session import SessionAdapter

#

L = logging.getLogger(__name__)

#


class SearchParams:
	"""
	Parse and validate standard search parameters from request query
	"""
	def __init__(
		self, query: typing.Mapping, *,
		page_default=0,
		items_per_page_default=10,
		simple_filter_default=None
	):
		# Set defaults
		self.Page: int | None = page_default
		self.ItemsPerPage: int | None = items_per_page_default
		self.SimpleFilter: str | None = simple_filter_default
		self.AdvancedFilter: dict = {}
		self.SortBy: list = []

		# Load actual parameter values from the query dict
		for k, v in query.items():
			if k == "p":
				try:
					v = int(v)
					assert v >= 1
				except (ValueError, AssertionError) as e:
					raise asab.exceptions.ValidationError(
						"The value of `p` (page) query parameter must be a positive integer, not {!r}".format(v)
					) from e
				self.Page = v - 1  # Page number is 1-indexed

			elif k in {"i", "l"}:
				try:
					v = int(v)
					assert v >= 1
				except (ValueError, AssertionError) as e:
					raise asab.exceptions.ValidationError(
						"The value of `i` or `l` (items per page) query parameter must be a positive integer, "
						"not {!r}".format(v)
					) from e
				self.ItemsPerPage = v

			elif k == "f":
				self.SimpleFilter = v

			elif k.startswith("a"):
				self.AdvancedFilter[k[1:]] = v

			elif k.startswith("s") and v in {"a", "d"}:
				self.SortBy.append((k[1:], v))

			# Ignore any other parameter

	def asdict(self):
		d = {}
		if self.Page is not None:
			d["page"] = self.Page
		if self.ItemsPerPage is not None:
			d["items_per_page"] = self.ItemsPerPage
		if self.SimpleFilter is not None:
			d["simple_filter"] = self.SimpleFilter
		if self.AdvancedFilter:
			d["advanced_filter"] = self.AdvancedFilter
		if self.SortBy:
			d["sort_by"] = self.SortBy
		return d

	def __repr__(self):
		return "SearchParams({})".format(", ".join(
			"{}={}".format(k, repr(v))
			for k, v in self.asdict().items()
		))


def get_bearer_token_value(request):
	bearer_prefix = "Bearer "
	auth_header = request.headers.get(aiohttp.hdrs.AUTHORIZATION, None)
	if auth_header is None:
		L.info("Request has no Authorization header")
		return None
	if auth_header.startswith(bearer_prefix):
		return auth_header[len(bearer_prefix):]

	L.info("No Bearer token in Authorization header")
	return None


def get_access_token_value_from_websocket(request):
	token_prefix = "access_token_"
	ws_protocol_header: str = request.headers.get(aiohttp.hdrs.SEC_WEBSOCKET_PROTOCOL)
	if ws_protocol_header is None:
		L.info("Request has no 'Sec-WebSocket-Protocol' header")
		return None
	for value in ws_protocol_header.split(", "):
		if value.startswith(token_prefix):
			return value[len(token_prefix):]

	L.info("No access token in Sec-WebSocket-Protocol header")
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
		if session.Authentication.LoginFactors is not None:
			headers["X-Login-Factors"] = " ".join(session.Authentication.LoginFactors)

	# Obtain login descriptor IDs from session object
	if "ldid" in attributes_to_add:
		if session.Authentication.LoginDescriptor is not None:
			headers["X-Login-Descriptor"] = session.Authentication.LoginDescriptor

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

	id_token = await oidc_service.issue_id_token(session)

	# Set the authorization header
	headers = {
		aiohttp.hdrs.AUTHORIZATION: "Bearer {}".format(id_token)
	}

	# Delete SeaCat cookie from header unless "keepcookie" param is passed in query
	cookie_string = request.headers.get(aiohttp.hdrs.COOKIE, "")
	if not request.query.get("keepcookie"):
		headers[aiohttp.hdrs.COOKIE] = cookie_service.remove_seacat_cookies_from_request(cookie_string)
	else:
		headers[aiohttp.hdrs.COOKIE] = cookie_string

	ws_prorocol = request.headers.get(aiohttp.hdrs.SEC_WEBSOCKET_PROTOCOL)
	if ws_prorocol:
		headers[aiohttp.hdrs.SEC_WEBSOCKET_PROTOCOL] = re.sub(r"access_token_[^ ,]+(, )?", "", ws_prorocol)

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


def update_url_query_params(url: str, **params):
	parsed = urlparse(url)
	query = {}
	for k, v in urllib.parse.parse_qsl(parsed["query"]):
		if k in query:
			raise ValueError("Repeated query parameters ({!r}) are not supported.".format(k))
		query[k] = v
	query.update(params)
	parsed["query"] = urllib.parse.urlencode(query)
	return urlunparse(**parsed)


def get_request_access_ips(request) -> list:
	access_ips = [request.remote]
	ff = request.headers.get("X-Forwarded-For")
	if ff is not None:
		access_ips.extend(ff.split(", "))
	return access_ips


def bcrypt_hash(secret: bytes | str) -> str:
	if isinstance(secret, str):
		secret = secret.encode("utf-8")
	return bcrypt.hashpw(secret, bcrypt.gensalt()).decode("utf-8")


def bcrypt_verify(hash: bytes | str, secret: bytes | str) -> bool:
	if isinstance(hash, str):
		hash = hash.encode("utf-8")
	if isinstance(secret, str):
		secret = secret.encode("utf-8")
	return bcrypt.checkpw(secret, hash)


def argon2_hash(secret: bytes | str) -> str:
	return argon2.PasswordHasher().hash(secret)


def argon2_verify(hash: bytes | str, secret: bytes | str) -> bool:
	try:
		return argon2.PasswordHasher().verify(hash, secret)
	except argon2.exceptions.VerifyMismatchError:
		return False


def generate_ergonomic_token(length: int):
	'''
	This function generates random string that is "ergonomic".
	This means that it contains only the letters and numbers that are unlikely to be misread by people.
	'''
	assert (length >= 1)
	return ''.join(random.choice(ergonomic_characters) for _ in range(length))


# These are characters that are safe (prevents confusion with other characters)
ergonomic_characters = "23456789abcdefghjkmnpqrstuvxyz"
