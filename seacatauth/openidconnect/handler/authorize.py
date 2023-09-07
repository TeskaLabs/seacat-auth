import logging
import urllib
import urllib.parse

import aiohttp
import aiohttp.web
import asab

from ...audit import AuditCode
from ...authz import build_credentials_authz
from ...cookie.utils import delete_cookie
from ... import client
from ... import exceptions
from ..utils import AuthErrorResponseCode
from ..pkce import InvalidCodeChallengeMethodError, InvalidCodeChallengeError
from ...generic import urlparse, urlunparse

#

L = logging.getLogger(__name__)

#


class OAuthAuthorizeError(Exception):
	def __init__(
		self, error, client_id,
		error_description=None,
		redirect_uri=None,
		state=None,
		credentials_id=None,
		struct_data=None
	):
		self.Error = error
		self.ClientId = client_id
		self.ErrorDescription = error_description
		self.RedirectUri = redirect_uri
		self.StructData = struct_data or {}
		self.CredentialsId = credentials_id
		self.State = state


class AuthorizeHandler(object):
	"""
	OAuth 2.0 Authorize

	OpenID Connect Core 1.0

	https://openid.net/specs/openid-connect-core-1_0.html

	---
	tags: ["OAuth 2.0 / OpenID Connect"]
	"""

	AuthorizePath = "/openidconnect/authorize"

	def __init__(self, app, oidc_svc, credentials_svc, public_api_base_url, auth_webui_base_url):
		self.App = app
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.CookieService = app.get_service("seacatauth.CookieService")
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")

		self.OpenIdConnectService = oidc_svc
		self.CredentialsService = credentials_svc

		if public_api_base_url.endswith("/"):
			self.PublicApiBaseUrl = public_api_base_url[:-1]
		else:
			self.PublicApiBaseUrl = public_api_base_url

		if auth_webui_base_url.endswith("/"):
			self.AuthWebuiBaseUrl = auth_webui_base_url[:-1]
		else:
			self.AuthWebuiBaseUrl = auth_webui_base_url

		self.LoginPath = "/#/login"
		self.HomePath = "/#/"

		web_app = app.WebContainer.WebApp
		web_app.router.add_get(self.AuthorizePath, self.authorize_get)
		web_app.router.add_post(self.AuthorizePath, self.authorize_post)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get(self.AuthorizePath, self.authorize_get)
		web_app_public.router.add_post(self.AuthorizePath, self.authorize_post)


	async def authorize_get(self, request):
		"""
		OAuth 2.0 Authorize Endpoint

		https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

		3.1.2.1.  Authentication Request

		If using the HTTP GET method, the request parameters are serialized using URI Query String Serialization

		---
		parameters:
		-	name: response_type
			in: query
			required: true
			description:
				The type of response desired from the Authorization Endpoint.
				This must be set to "code" for the authorization code grant flow
				or "id_token" for the implicit flow.
			schema:
				type: string
				enum: ["code", "id_token"]
		-	name: client_id
			in: query
			required: true
			description:
				The client identifier registered with the Authorization Server.
			schema:
				type: string
		-	name: redirect_uri
			in: query
			required: true
			description:
				The redirection URI to which the response will be sent.
				This URI must be registered with the Authorization Server.
			schema:
				type: string
		-	name: scope
			in: query
			required: false
			description:
				The scope of the access request as described by the Authorization Server.
			schema:
				type: string
		-	name: state
			in: query
			required: false
			description:
				An opaque value used by the client to maintain state between the request and callback.
				The Authorization Server will include this value when redirecting the user back to the client.
			schema:
				type: string
		-	name: prompt
			in: query
			required: false
			description:
				Space delimited, case-sensitive list of ASCII string values that specifies whether the
				Authorization Server prompts the End-User for re-authentication and consent.
			schema:
				type: string
				enum: ["login", "none", "select_account"]
		-	name: code_challenge
			in: query
			required: false
			description:
				A challenge derived from the code verifier that is sent in the authorization request, to be
				verified against later.
			schema:
				type: string
		-	name: code_challenge_method
			in: query
			required: false
			description:
				A method that was used to derive code challenge.
			schema:
				type: string
				enum: ["S256", "plain"]
		"""
		try:
			return await self.authorize(request, request.query)
		except OAuthAuthorizeError as e:
			await self.audit_authorize_error(e)
			return self.reply_with_authentication_error(
				e.Error, e.RedirectUri,
				error_description=e.ErrorDescription,
				state=e.State)


	async def authorize_post(self, request):
		"""
		OAuth 2.0 Authorize Endpoint

		https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

		3.1.2.1.  Authentication Request

		If using the HTTP POST method, the request parameters are serialized using Form Serialization
		"""
		request_parameters = await request.post()
		return await self.authorize(request, request_parameters)


	async def authorize(self, request, request_parameters):
		"""
		https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

		3.1.2.1.  Authentication Request
		"""

		# Check the presence of required parameters
		self._validate_request_parameters(request_parameters)

		# TODO: Remove this. These extra options should either be in scope or in client config.
		login_parameters = {
			k: v for k, v in request_parameters.items()
			if k in frozenset(("ldid",))
		}

		# Authentication Code Flow
		assert request_parameters["response_type"] == "code"
		return await self.authentication_code_flow(
			request,
			scope=request_parameters["scope"].split(" "),
			client_id=request_parameters["client_id"],
			redirect_uri=request_parameters["redirect_uri"],
			client_secret=request_parameters.get("client_secret"),
			state=request_parameters.get("state"),
			prompt=request_parameters.get("prompt"),
			code_challenge=request_parameters.get("code_challenge"),
			code_challenge_method=request_parameters.get("code_challenge_method", "none"),
			login_parameters=login_parameters
		)


	async def authentication_code_flow(
		self,
		request,
		scope: list,
		client_id: str,
		redirect_uri: str,
		client_secret: str = None,
		state: str = None,
		prompt: str = None,
		code_challenge: str = None,
		code_challenge_method: str = None,
		login_parameters: dict = None,
	):
		"""
		https://openid.net/specs/openid-connect-core-1_0.html

		Authentication Code Flow
		"""
		# Authorize the client and check that all the request parameters are valid by the client's settings
		try:
			client_dict = await self._authorize_client(client_id, redirect_uri, client_secret)
		except OAuthAuthorizeError as e:
			e.State = state
			e.RedirectUri = redirect_uri
			raise e

		# Extract request source
		from_info = [request.remote]
		ff = request.headers.get("X-Forwarded-For")
		if ff is not None:
			from_info.extend(ff.split(", "))

		# Decide whether this is an openid or cookie request
		try:
			authorize_type = await self._get_authorize_type(client_id, scope)
		except OAuthAuthorizeError as e:
			e.RedirectUri = redirect_uri
			e.State = state
			raise e

		if authorize_type == "openid":
			try:
				code_challenge_method = self.OpenIdConnectService.PKCE.validate_code_challenge_initialization(
					client_dict, code_challenge, code_challenge_method)
			except InvalidCodeChallengeMethodError:
				L.error("Invalid code challenge method.", struct_data={
					"client_id": client_id, "method": code_challenge_method})
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.InvalidRequest, client_id,
					redirect_uri=redirect_uri,
					state=state,
					struct_data={"reason": "code_challenge_error"})
			except InvalidCodeChallengeError:
				L.error("Invalid code challenge request.", struct_data={
					"client_id": client_id, "method": code_challenge_method, "challenge": code_challenge})
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.InvalidRequest, client_id,
					redirect_uri=redirect_uri,
					state=state,
					struct_data={"reason": "code_challenge_error"})
		elif code_challenge is not None:
			L.error("Code challenge not supported for cookie authorization.", struct_data={
				"client_id": client_id})
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidRequest, client_id,
				redirect_uri=redirect_uri,
				state=state,
				struct_data={"reason": "code_challenge_error"})

		# Only root sessions can be used to authorize client sessions
		root_session = request.Session
		if root_session is not None:
			if root_session.Session.Type != "root":
				L.warning("Session type must be 'root'", struct_data={"sid": root_session.Id, "type": root_session.Session.Type})
				root_session = None
			elif root_session.is_anonymous() and not client_dict.get("authorize_anonymous_users", False):
				L.warning("Not allowed to authorize with anonymous session.", struct_data={
					"sid": root_session.Id, "client_id": client_id})
				root_session = None

		authenticated = root_session is not None and not root_session.is_anonymous()
		allow_anonymous = "anonymous" in scope
		if allow_anonymous and not client_dict.get("authorize_anonymous_users", False):
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidScope, client_id,
				redirect_uri=redirect_uri,
				state=state,
				struct_data={"reason": "anonymous_access_not_allowed"})

		session_expiration = client_dict.get("session_expiration")

		# Check if we need to redirect to login and authenticate
		if authenticated:
			if prompt == "login":
				# Delete current session and redirect to login
				await self.SessionService.delete(root_session.SessionId)
				return await self.reply_with_redirect_to_login(
					response_type="code",
					scope=scope,
					client_id=client_id,
					redirect_uri=redirect_uri,
					state=state,
					code_challenge=code_challenge,
					code_challenge_method=code_challenge_method,
					login_parameters=login_parameters)
			elif prompt == "select_account":
				# Redirect to login without deleting current session
				return await self.reply_with_redirect_to_login(
					response_type="code",
					scope=scope,
					client_id=client_id,
					redirect_uri=redirect_uri,
					state=state,
					code_challenge=code_challenge,
					code_challenge_method=code_challenge_method,
					login_parameters=login_parameters)

		elif allow_anonymous:
			# Create anonymous session or redirect to login if requested
			if prompt == "login" or prompt == "select_account":
				return await self.reply_with_redirect_to_login(
					response_type="code",
					scope=scope,
					client_id=client_id,
					redirect_uri=redirect_uri,
					state=state,
					code_challenge=code_challenge,
					code_challenge_method=code_challenge_method,
					login_parameters=login_parameters)

		else:  # NOT authenticated and NOT allowing anonymous access
			# Redirect to login unless prompt=none requested
			if prompt == "none":
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.LoginRequired, client_id,
					redirect_uri=redirect_uri,
					state=state)
			return await self.reply_with_redirect_to_login(
				response_type="code",
				scope=scope,
				client_id=client_id,
				redirect_uri=redirect_uri,
				state=state,
				code_challenge=code_challenge,
				code_challenge_method=code_challenge_method,
				login_parameters=login_parameters)

		# Here the request must be authenticated or anonymous access must be allowed
		assert authenticated or allow_anonymous

		if authenticated:
			# Authentication successful, we can open a new client session
			assert root_session is not None

			# Redirect to factor management page if (re)setting of any factor is required
			# TODO: Move this check to AuthenticationService.login, add "restricted" flag to the root session
			factors_to_setup = await self._get_factors_to_setup(root_session)
			if len(factors_to_setup) > 0:
				L.log(asab.LOG_NOTICE, "Auth factor setup required. Redirecting to setup.", struct_data={
					"missing_factors": " ".join(factors_to_setup), "cid": root_session.Credentials.Id})
				return await self.reply_with_factor_setup_redirect(
					session=root_session,
					missing_factors=factors_to_setup,
					response_type="code",
					scope=scope,
					client_id=client_id,
					redirect_uri=redirect_uri,
					state=state,
					login_parameters=login_parameters
				)

			# Authorize access to tenants requested in scope
			try:
				tenants = await self.authorize_tenants_by_scope(
					scope, root_session.Authorization.Authz, root_session.Credentials.Id, client_id)
			except exceptions.AccessDeniedError:
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.AccessDenied, client_id,
					redirect_uri=redirect_uri,
					state=state,
					struct_data={"reason": "tenant_not_found"})

			if authorize_type == "openid":
				new_session = await self.OpenIdConnectService.create_oidc_session(
					root_session, client_id, scope,
					tenants=tenants,
					requested_expiration=session_expiration)
			elif authorize_type == "cookie":
				new_session = await self.CookieService.create_cookie_client_session(
					root_session, client_id, scope, tenants,
					requested_expiration=session_expiration)
				# Cookie flow implicitly redirects to the cookie entry point and puts the final redirect_uri in the query
				redirect_uri = await self._build_cookie_entry_redirect_uri(client_dict, redirect_uri)
			else:
				raise ValueError("Unexpected authorize_type: {}".format(authorize_type))

		else:  # Not authenticated, but it is allowed to open a new anonymous session
			assert allow_anonymous
			assert root_session is None  # There are no anonymous root sessions

			# Create algorithmic anonymous session without root

			# Validate the anonymous credentials
			anonymous_cid = client_dict.get("anonymous_cid")
			try:
				await self.CredentialsService.get(anonymous_cid)
			except KeyError:
				L.error("Credentials for anonymous access not found.", struct_data={
					"cid": anonymous_cid, "client_id": client_id})
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.AccessDenied, client_id,
					redirect_uri=redirect_uri,
					state=state,
					struct_data={"reason": "credentials_not_found"})

			# Get credentials' assigned tenants and resources
			authz = await build_credentials_authz(
				self.OpenIdConnectService.TenantService, self.OpenIdConnectService.RoleService, anonymous_cid)

			# Authorize access to tenants requested in scope
			try:
				tenants = await self.authorize_tenants_by_scope(
					scope, authz, anonymous_cid, client_id)
			except exceptions.AccessDeniedError:
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.AccessDenied, client_id,
					redirect_uri=redirect_uri,
					state=state,
					struct_data={"reason": "tenant_not_found"})

			if authorize_type == "openid":
				new_session = await self.OpenIdConnectService.create_anonymous_oidc_session(
					anonymous_cid, client_dict, scope,
					tenants=tenants,
					from_info=from_info)
			elif authorize_type == "cookie":
				new_session = await self.CookieService.create_anonymous_cookie_client_session(
					anonymous_cid, client_dict, scope,
					tenants=tenants,
					from_info=from_info)
				# Cookie flow implicitly redirects to the cookie entry point and puts the final redirect_uri in the query
				redirect_uri = await self._build_cookie_entry_redirect_uri(client_dict, redirect_uri)
			else:
				raise ValueError("Unexpected authorize_type: {!r}".format(authorize_type))

			# Anonymous sessions need to be audited
			await self.OpenIdConnectService.AuditService.append(
				AuditCode.ANONYMOUS_SESSION_CREATED,
				credentials_id=new_session.Credentials.Id,
				client_id=client_id,
				scope=scope,
				session_id=str(new_session.SessionId),
				fi=from_info)

		await self.audit_authorize_success(new_session, from_info)
		return await self.reply_with_successful_response(
			new_session, scope, redirect_uri, state,
			code_challenge=code_challenge,
			code_challenge_method=code_challenge_method)

	async def _build_cookie_entry_redirect_uri(self, client_dict, redirect_uri):
		cookie_entry_uri = client_dict.get("cookie_entry_uri")
		if cookie_entry_uri is None:
			L.error("Client has no cookie_entry_uri configured.", struct_data={"client_id": client_dict["_id"]})
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidRequest, client_dict["_id"],
				redirect_uri=redirect_uri,
				struct_data={"reason": "cookie_entry_uri_not_configured"})
		else:
			# TODO: More clever formatting (what if the cookie_entry_uri already has a query)
			return "{}?{}".format(
				cookie_entry_uri,
				urllib.parse.urlencode([
					("client_id", client_dict["_id"]),  # TODO: Remove, this should be a client responsibility
					("grant_type", "authorization_code"),  # TODO: Remove, this should be a client responsibility
					("redirect_uri", redirect_uri)]))


	async def _authorize_client(self, client_id, redirect_uri, client_secret=None):
		try:
			client_dict = await self.OpenIdConnectService.ClientService.get(client_id)
		except KeyError:
			L.error("Client ID not found.", struct_data={"client_id": client_id})
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidRequest, client_id,
				struct_data={"reason": "client_id_not_found"})
		try:
			await self.OpenIdConnectService.ClientService.authorize_client(
				client=client_dict,
				client_secret=client_secret,
				redirect_uri=redirect_uri,
				response_type="code",
			)
		except client.exceptions.InvalidClientSecret:
			L.error("Invalid client secret.", struct_data={"client_id": client_id})
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.UnauthorizedClient, client_id)
		except client.exceptions.InvalidRedirectURI:
			L.error("Invalid client secret.", struct_data={"client_id": client_id})
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidRequest, client_id,
				struct_data={"reason": "invalid_redirect_uri"})
		except client.exceptions.ClientError as e:
			L.error("Generic client error: {}".format(e), struct_data={"client_id": client_id})
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidRequest, client_id)
		return client_dict


	async def _get_authorize_type(self, client_id, scope):
		if "openid" in scope:
			# OpenID Connect requests MUST contain the openid scope value.
			# Otherwise, the request is not considered OpenID and its behavior is unspecified
			if "cookie" in scope:
				L.warning("Scope cannot contain 'openid' and 'cookie' at the same time.", struct_data={
					"scope": " ".join(scope)})
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.InvalidScope, client_id,
					error_description="Scope cannot contain 'openid' and 'cookie' at the same time.",
					struct_data={"scope": scope})
			return "openid"

		elif "cookie" in scope:
			return "cookie"

		else:
			L.warning("Scope must contain 'openid' or 'cookie'.", struct_data={"scope": " ".join(scope)})
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidScope, client_id,
				error_description="Scope must contain 'openid' or 'cookie'.",
				struct_data={"scope": scope})

	async def _get_factors_to_setup(self, session):
		factors_to_setup = []

		# Check if all the enforced factors are present in the session
		if self.AuthenticationService.EnforceFactors is not None:
			factors_to_setup = list(self.AuthenticationService.EnforceFactors)
			for factor in session.Authentication.LoginDescriptor["factors"]:
				if factor["type"] in factors_to_setup:
					factors_to_setup.remove(factor["type"])

		# Check if there are additional factors to be reset
		credentials = await self.CredentialsService.get(session.Credentials.Id)
		cred_enforce_factors = set(credentials.get("enforce_factors", []))
		for factor in cred_enforce_factors:
			if factor not in factors_to_setup:
				factors_to_setup.append(factor)

		return factors_to_setup


	async def reply_with_successful_response(
		self, session, scope: list, redirect_uri: str,
		state: str = None,
		code_challenge: str = None,
		code_challenge_method: str = None
	):
		"""
		https://openid.net/specs/openid-connect-core-1_0.html
		3.1.2.5.  Successful Authentication Response

		The OAuth 2.0 Authorization Framework
		https://tools.ietf.org/html/rfc6749#section-4.1.2
		4.1.2.  Authorization Response
		"""

		# Prepare the redirect URL
		url = urllib.parse.urlparse(redirect_uri)
		url_qs = urllib.parse.parse_qs(url.query)

		if state is not None:
			# The OAuth 2.0 Authorization Framework, 4.1.2.  Authorization Response
			# If the "state" parameter was present in the client authorization request,
			# then use the exact value received from the client.
			url_qs["state"] = state

		# Add the Authorization Code into the response
		url_qs["code"] = await self.OpenIdConnectService.generate_authorization_code(
			session,
			code_challenge=code_challenge,
			code_challenge_method=code_challenge_method
		)

		# Success
		url = urllib.parse.urlunparse((
			url.scheme,
			url.netloc,
			url.path,
			url.params,
			urllib.parse.urlencode(url_qs, doseq=True),
			url.fragment  # TODO: There should be no fragment in redirect URI
		))

		response = aiohttp.web.HTTPFound(
			url,
			headers={
				# TODO: The server SHOULD generate a Location header field
				# https://httpwg.org/specs/rfc7231.html#status.302
				"Refresh": '0;url=' + url,
			},
			content_type="text/html",
			text="""<!doctype html>\n<html lang="en">\n<head></head><body>...</body>\n</html>\n"""
		)

		return response


	async def reply_with_redirect_to_login(
		self, response_type: str, scope: list, client_id: str, redirect_uri: str,
		state: str = None,
		code_challenge: str = None,
		code_challenge_method: str = None,
		login_parameters: dict = None
	):
		"""
		Reply with 404 and provide a link to the login form with a loopback to OIDC/authorize.
		Pass on the query parameters.
		"""

		# Gather params which will be passed to the login page
		login_query_params = []
		if login_parameters is not None:
			login_query_params = list(login_parameters.items())

		# Gather params which will be passed to the after-login oidc/authorize call
		authorize_query_params = {
			"response_type": response_type,
			"scope": " ".join(scope),
			"client_id": client_id,
			"redirect_uri": redirect_uri,
		}

		if state is not None:
			authorize_query_params["state"] = state

		if code_challenge is not None:
			authorize_query_params["code_challenge"] = code_challenge
			if code_challenge_method not in (None, "none"):
				authorize_query_params["code_challenge_method"] = code_challenge_method

		# Get client collection
		client_dict = await self.OpenIdConnectService.ClientService.get(client_id)

		# Build redirect uri
		callback_uri = self.OpenIdConnectService.build_authorize_uri(client_dict, **authorize_query_params)

		login_query_params.append(("redirect_uri", callback_uri))
		login_query_params.append(("client_id", client_id))

		# Build login uri
		login_url = self._build_login_uri(client_dict, login_query_params)
		response = aiohttp.web.HTTPNotFound(
			headers={
				"Location": login_url,
				"Refresh": '0;url=' + login_url,
			},
			content_type="text/html",
			text="""<!doctype html>\n<html lang="en">\n<head></head><body>...</body>\n</html>\n"""
		)
		delete_cookie(self.App, response)
		return response

	async def reply_with_factor_setup_redirect(
		self, session, missing_factors: list,
		response_type: str, scope: list, client_id: str, redirect_uri: str,
		state: str = None,
		login_parameters: dict = None
	):
		"""
		Redirect to home screen and force factor (re)configuration
		"""
		# Prepare the redirect URL
		sfa_url = urllib.parse.urlparse("{}{}".format(
			self.AuthWebuiBaseUrl,
			self.HomePath
		))

		# Gather params which will be passed to the oidc/authorize request called after the OTP setup
		authorize_query_params = [
			("prompt", "login"),
			("response_type", response_type),
			("scope", " ".join(scope)),
			("client_id", client_id),
			("redirect_uri", redirect_uri),
		]
		if state is not None:
			authorize_query_params.append(("state", state))

		# Build the redirect URI back to this endpoint and add it to auth URL params
		authorize_redirect_uri = "{}{}?{}".format(
			self.PublicApiBaseUrl,
			self.AuthorizePath,
			urllib.parse.urlencode(authorize_query_params)
		)

		auth_url_params = [
			("setup", " ".join(missing_factors)),
			# Redirect URI needs an extra layer of percent-encoding when placed in fragment
			# because browsers automatically do one layer of decoding
			("redirect_uri", urllib.parse.quote(authorize_redirect_uri))
		]
		# Add the query params to the #fragment part
		# TODO: There should be no fragment in redirect URI. Move to regular query.
		fragment = "{}?{}".format(sfa_url.fragment, urllib.parse.urlencode(auth_url_params, doseq=True))

		sfa_url = urllib.parse.urlunparse((
			sfa_url.scheme,
			sfa_url.netloc,
			sfa_url.path,
			sfa_url.params,
			None,
			fragment
		))

		response = aiohttp.web.HTTPFound(
			sfa_url,
			headers={
				"Refresh": "0;url=" + sfa_url,
			},
			content_type="text/html",
			text="""<!doctype html>\n<html lang="en">\n<head></head><body>...</body>\n</html>\n"""
		)

		return response

	def reply_with_authentication_error(
		self, error: str, redirect_uri: str,
		error_description: str = None,
		error_uri: str = None,
		state: str = None
	):
		"""
		3.1.2.6.  Authentication Error Response

		Unless the Redirection URI is invalid, the Authorization Server returns the Client to the Redirection
		URI specified in the Authorization Request with the appropriate error and state parameters.
		Other parameters SHOULD NOT be returned.
		"""
		qs = {}
		qs["error"] = error
		if error_description is not None:
			qs["error_description"] = error_description
		if error_uri is not None:
			qs["error_uri"] = error_uri
		if state is not None:
			qs["state"] = state

		if redirect_uri is not None:
			# Redirect to redirect_uri
			parts = urllib.parse.urlparse(redirect_uri)
			for k, v in urllib.parse.parse_qs(parts.query).items():
				if k not in qs:
					qs[k] = v.pop()
			redirect = urllib.parse.urlunparse((
				parts.scheme,
				parts.netloc,
				parts.path,
				None,  # params
				urllib.parse.urlencode(qs),
				None,
			))
		else:
			# No redirect_uri -> redirect to UI login page
			# TODO: Use the /message page on frontend
			redirect = "{}{}?{}".format(
				self.AuthWebuiBaseUrl,
				self.LoginPath,
				urllib.parse.urlencode(qs)
			)
		return aiohttp.web.HTTPFound(redirect)

	async def audit_authorize_success(self, session, from_info):
		await self.OpenIdConnectService.AuditService.append(
			AuditCode.AUTHORIZE_SUCCESS,
			credentials_id=session.Credentials.Id,
			client_id=session.OAuth2.ClientId,
			session_id=str(session.Session.Id),
			scope=session.OAuth2.Scope,
			tenants=[t for t in session.Authorization.Authz if t != "*"],
			fi=from_info)


	async def audit_authorize_error(self, error: OAuthAuthorizeError):
		await self.OpenIdConnectService.AuditService.append(
			AuditCode.AUTHORIZE_ERROR,
			credentials_id=error.CredentialsId,
			client_id=error.ClientId,
			**error.StructData)


	async def authorize_tenants_by_scope(self, scope, authz, credentials_id, client_id):
		has_access_to_all_tenants = self.OpenIdConnectService.RBACService.has_resource_access(
			authz, tenant=None, requested_resources=["authz:superuser"]) \
			or self.OpenIdConnectService.RBACService.has_resource_access(
			authz, tenant=None, requested_resources=["authz:tenant:access"])
		try:
			tenants = await self.OpenIdConnectService.TenantService.get_tenants_by_scope(
				scope, credentials_id, has_access_to_all_tenants)
		except exceptions.TenantNotFoundError as e:
			L.error("Tenant not found", struct_data={"tenant": e.Tenant})
			raise exceptions.AccessDeniedError(subject=credentials_id)
		except exceptions.TenantAccessDeniedError as e:
			L.error("Tenant access denied", struct_data={"tenant": e.Tenant, "cid": credentials_id})
			raise exceptions.AccessDeniedError(subject=credentials_id)
		except exceptions.NoTenantsError:
			L.error("Tenant access denied", struct_data={"cid": credentials_id})
			raise exceptions.AccessDeniedError(subject=credentials_id)

		return tenants


	def _build_login_uri(self, client_dict, login_query_params):
		"""
		Check if the client has a registered login URI. If not, use the default.
		Extend the URI with query parameters.
		"""
		login_uri = client_dict.get("login_uri")
		if login_uri is None:
			login_uri = "{}{}".format(self.AuthWebuiBaseUrl, self.LoginPath)

		parsed = urlparse(login_uri)
		if parsed["fragment"] != "":
			# If the Login URI contains fragment, add the login params into the fragment query
			fragment_parsed = urlparse(parsed["fragment"])
			query = urllib.parse.parse_qs(fragment_parsed["query"])
			query.update(login_query_params)
			fragment_parsed["query"] = urllib.parse.urlencode(query)
			parsed["fragment"] = urlunparse(**fragment_parsed)
		else:
			# If the Login URI contains no fragment, add the login params into the regular URL query
			query = urllib.parse.parse_qs(parsed["query"])
			query.update(login_query_params)
			parsed["query"] = urllib.parse.urlencode(query)

		return urlunparse(**parsed)


	def _validate_request_parameters(self, request_parameters):
		state = request_parameters.get("state") or None

		# Check for required parameters
		client_id = request_parameters.get("client_id") or None
		if client_id is None:
			L.warning("Missing or empty required parameter: {}.".format("client_id"), struct_data=request_parameters)
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidRequest, client_id,
				redirect_uri=request_parameters.get("redirect_uri"),
				error_description="Missing or empty parameter {!r}.".format("client_id"),
				state=state,
				struct_data={"reason": "missing_query_parameter"})

		# NOTE: "redirect_uri" is required only by OIDC, not generic OAuth
		redirect_uri = request_parameters.get("redirect_uri") or None
		if redirect_uri is None:
			L.warning("Missing or empty required parameter: {}.".format("redirect_uri"), struct_data=request_parameters)
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidRequest, client_id,
				redirect_uri=redirect_uri,
				error_description="Missing or empty parameter {!r}.".format("redirect_uri"),
				state=state,
				struct_data={"reason": "missing_query_parameter"})

		response_type = request_parameters.get("response_type") or None
		if response_type is None:
			L.warning(
				"Missing or empty required parameter: {}.".format("response_type"), struct_data=request_parameters)
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidRequest, client_id,
				redirect_uri=redirect_uri,
				error_description="Missing or empty parameter {!r}.".format("response_type"),
				state=state,
				struct_data={"reason": "missing_query_parameter"})
		elif response_type != "code":
			L.warning("Unsupported response type.", struct_data=request_parameters)
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.UnsupportedResponseType, client_id,
				redirect_uri=redirect_uri,
				state=state)

		# NOTE: "scope" is required only by OIDC, not generic OAuth
		scope = request_parameters.get("scope") or None
		if scope is None:
			L.warning("Missing or empty required parameter: {}.".format("scope"), struct_data=request_parameters)
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidRequest, client_id,
				redirect_uri=redirect_uri,
				error_description="Missing or empty parameter {!r}.".format("scope"),
				state=state,
				struct_data={"reason": "missing_query_parameter"})

		prompt = request_parameters.get("prompt") or None
		if prompt is not None:
			# TODO: Prompt can be a list of multiple values (e.g. "prompt=select_account,consent")
			if prompt not in frozenset(["none", "login", "select_account"]):
				L.warning("Unsupported prompt.", struct_data={"prompt": prompt})
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.InvalidRequest, client_id,
					error_description="Invalid prompt value: {}".format(prompt),
					redirect_uri=redirect_uri,
					state=state)
			L.info("Prompt {!r} requested.".format(prompt))

		# Check non-standard authorize parameters
		# TODO: Move these parameters to client configuration instead
		for parameter in frozenset(["ldid", "expiration"]):
			if parameter in request_parameters:
				L.info("Using non-standard authorize parameter {!r}.".format(parameter))

		# TODO: Move code challenge method validation here
