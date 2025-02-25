import logging
import urllib
import urllib.parse
import aiohttp
import aiohttp.web
import asab

from ..service import AuthorizationCode
from ...authz import build_credentials_authz
from ... import generic, AuditLogger
from ... import exceptions
from ..utils import AuthErrorResponseCode, AUTHORIZE_PARAMETERS
from ..pkce import InvalidCodeChallengeMethodError, InvalidCodeChallengeError
from ...last_activity import EventCode


L = logging.getLogger(__name__)


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


class ClientIdError(OAuthAuthorizeError):
	def __init__(self, client_id, credentials_id=None):
		super().__init__(
			"client_id_error",
			client_id=client_id,
			credentials_id=credentials_id)


class RedirectUriError(OAuthAuthorizeError):
	def __init__(self, redirect_uri, client_id=None, credentials_id=None):
		super().__init__(
			"redirect_uri_error",
			client_id=client_id,
			credentials_id=credentials_id,
			redirect_uri=redirect_uri)


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

		self.PublicApiBaseUrl = public_api_base_url
		self.AuthWebuiBaseUrl = auth_webui_base_url

		self.LoginPath = "#/login"
		self.HomePath = "#/"

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
		-	name: nonce
			in: query
			required: false
			description:
				String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
				The value is passed through unmodified from the Authentication Request to the ID Token.
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
		access_ips = generic.get_request_access_ips(request)
		# Authorization Servers SHOULD ignore unrecognized request parameters [RFC6749]
		supported_parameters = {
			k: v for k, v
			in request.query.items()
			if k in AUTHORIZE_PARAMETERS}

		try:
			return await self.authorize(request, supported_parameters)
		# If the request fails due to a missing, invalid, or mismatching redirection URI, or if the client identifier
		#   is missing or invalid, the authorization server SHOULD inform the resource owner of the error and MUST NOT
		#   automatically redirect the user-agent to the invalid redirection URI. (rfc6749#section-4.1.2.1)
		except ClientIdError as e:
			await self.audit_authorize_error(e, access_ips=access_ips)
			return aiohttp.web.HTTPBadRequest()
		except RedirectUriError as e:
			await self.audit_authorize_error(e, access_ips=access_ips)
			return aiohttp.web.HTTPBadRequest()
		#  If the resource owner denies the access request or if the request fails for reasons other than a missing or
		#    invalid redirection URI, the authorization server informs the client by adding the following parameters to
		#    the query component of the redirection URI. (rfc6749#section-4.1.2.1)
		except OAuthAuthorizeError as e:
			await self.audit_authorize_error(e, access_ips=access_ips)
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
		access_ips = generic.get_request_access_ips(request)
		# Authorization Servers SHOULD ignore unrecognized request parameters [RFC6749]
		supported_parameters = {
			k: v for k, v
			in request_parameters.items()
			if k in AUTHORIZE_PARAMETERS}

		try:
			return await self.authorize(request, supported_parameters)
		# If the request fails due to a missing, invalid, or mismatching redirection URI, or if the client identifier
		#   is missing or invalid, the authorization server SHOULD inform the resource owner of the error and MUST NOT
		#   automatically redirect the user-agent to the invalid redirection URI. (rfc6749#section-4.1.2.1)
		except ClientIdError as e:
			await self.audit_authorize_error(e, access_ips=access_ips)
			return aiohttp.web.HTTPBadRequest()
		except RedirectUriError as e:
			await self.audit_authorize_error(e, access_ips=access_ips)
			return aiohttp.web.HTTPBadRequest()
		#  If the resource owner denies the access request or if the request fails for reasons other than a missing or
		#    invalid redirection URI, the authorization server informs the client by adding the following parameters to
		#    the query component of the redirection URI. (rfc6749#section-4.1.2.1)
		except OAuthAuthorizeError as e:
			await self.audit_authorize_error(e, access_ips=access_ips)
			return self.reply_with_authentication_error(
				e.Error, e.RedirectUri,
				error_description=e.ErrorDescription,
				state=e.State)


	async def authorize(self, request, request_parameters):
		"""
		https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

		3.1.2.1.  Authentication Request
		"""
		# Check the presence of required parameters
		self._validate_request_parameters(request_parameters)

		# Authentication Code Flow
		assert request_parameters["response_type"] == "code"
		return await self.authorization_code_flow(request, **request_parameters)


	async def authorization_code_flow(
		self,
		request,
		scope: str,
		client_id: str,
		redirect_uri: str,
		state: str = None,
		nonce: str = None,
		prompt: str = None,
		code_challenge: str = None,
		code_challenge_method: str = None,
		**kwargs
	):
		"""
		https://openid.net/specs/openid-connect-core-1_0.html

		Authentication Code Flow
		"""
		requested_scope = scope.split(" ")
		granted_scope = set()

		# Authorize the client and check that all the request parameters are valid by the client's settings
		try:
			client_dict = await self._validate_client_options(client_id, redirect_uri, response_type="code")
		except OAuthAuthorizeError as e:
			e.State = state
			e.RedirectUri = redirect_uri
			raise e
		except exceptions.ClientNotFoundError as e:
			L.log(asab.LOG_NOTICE, "Client not found.", struct_data={"client_id": client_id, "redirect_uri": redirect_uri})
			raise ClientIdError(client_id) from e
		except exceptions.InvalidRedirectURI as e:
			L.log(asab.LOG_NOTICE, "Invalid redirect URI.", struct_data={"client_id": client_id, "redirect_uri": redirect_uri})
			raise RedirectUriError(redirect_uri, client_id) from e

		# Extract request source
		from_info = generic.get_request_access_ips(request)

		# Decide whether this is an openid or cookie request
		try:
			auth_token_type = await self._get_auth_token_type(client_id, requested_scope)
		except OAuthAuthorizeError as e:
			e.RedirectUri = redirect_uri
			e.State = state
			raise e
		granted_scope.add(auth_token_type)

		if auth_token_type == "openid":
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
			except InvalidCodeChallengeError as e:
				L.error("Invalid code challenge request: {}".format(e), struct_data={
					"client_id": client_id, "method": code_challenge_method, "challenge": code_challenge})
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.InvalidRequest, client_id,
					redirect_uri=redirect_uri,
					state=state,
					struct_data={"reason": "code_challenge_error"})
		elif auth_token_type == "cookie" and code_challenge is not None:
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
				L.error("Session type must be 'root'", struct_data={"sid": root_session.Id, "type": root_session.Session.Type})
				root_session = None
			elif root_session.is_anonymous() and not client_dict.get("authorize_anonymous_users", False):
				L.warning("Not allowed to authorize with anonymous session.", struct_data={
					"sid": root_session.Id, "client_id": client_id})
				root_session = None

		authenticated = root_session is not None and not root_session.is_anonymous()
		allow_anonymous = "anonymous" in requested_scope
		if allow_anonymous:
			if not client_dict.get("authorize_anonymous_users", False):
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.InvalidScope, client_id,
					redirect_uri=redirect_uri,
					state=state,
					struct_data={"reason": "anonymous_access_not_allowed"})
			granted_scope.add("anonymous")

		# Check if we need to redirect to login and authenticate
		if authenticated:
			if prompt == "login":
				# Delete current session and redirect to login
				await self.SessionService.delete(root_session.SessionId)
				L.log(asab.LOG_NOTICE, "Login prompt requested by client", struct_data={"client_id": client_id})
				return await self.reply_with_redirect_to_login(
					scope=requested_scope,
					client_id=client_id,
					redirect_uri=redirect_uri,
					state=state,
					nonce=nonce,
					code_challenge=code_challenge,
					code_challenge_method=code_challenge_method,
					**kwargs)
			elif prompt == "select_account":
				# Redirect to login without deleting current session
				L.log(asab.LOG_NOTICE, "Account selection prompt requested by client", struct_data={
					"client_id": client_id})
				return await self.reply_with_redirect_to_login(
					scope=requested_scope,
					client_id=client_id,
					redirect_uri=redirect_uri,
					state=state,
					nonce=nonce,
					code_challenge=code_challenge,
					code_challenge_method=code_challenge_method,
					**kwargs)

		elif allow_anonymous:
			# Create anonymous session or redirect to login if requested
			if prompt == "login" or prompt == "select_account":
				L.log(asab.LOG_NOTICE, "Account selection or login prompt requested by client", struct_data={
					"client_id": client_id})
				return await self.reply_with_redirect_to_login(
					scope=requested_scope,
					client_id=client_id,
					redirect_uri=redirect_uri,
					state=state,
					nonce=nonce,
					code_challenge=code_challenge,
					code_challenge_method=code_challenge_method,
					**kwargs)

		else:  # NOT authenticated and NOT allowing anonymous access
			# Redirect to login unless prompt=none requested
			if prompt == "none":
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.LoginRequired, client_id,
					redirect_uri=redirect_uri,
					state=state)
			L.log(asab.LOG_NOTICE, "Login required", struct_data={
				"client_id": client_id})
			return await self.reply_with_redirect_to_login(
				scope=requested_scope,
				client_id=client_id,
				redirect_uri=redirect_uri,
				state=state,
				nonce=nonce,
				code_challenge=code_challenge,
				code_challenge_method=code_challenge_method,
				**kwargs)

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
					missing_factors=factors_to_setup,
					response_type="code",
					scope=requested_scope,
					client_id=client_id,
					redirect_uri=redirect_uri,
					state=state,
				)

			# Authorize access to tenants requested in scope
			try:
				authorized_tenant = await self.OpenIdConnectService.get_accessible_tenant_from_scope(
					requested_scope, root_session.Credentials.Id,
					has_access_to_all_tenants=self.OpenIdConnectService.RBACService.can_access_all_tenants(
						root_session.Authorization.Authz)
				)
			except exceptions.NoTenantsError:
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.NoTenants, client_id,
					redirect_uri=redirect_uri,
					state=state,
				)
			except exceptions.AccessDeniedError:
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.TenantAccessDenied, client_id,
					redirect_uri=redirect_uri,
					state=state,
				)

			if auth_token_type == "openid":
				new_session = await self.OpenIdConnectService.create_oidc_session(
					root_session, client_id, requested_scope,
					nonce=nonce,
					redirect_uri=redirect_uri,
					tenants=[authorized_tenant] if authorized_tenant else None,
					requested_expiration=AuthorizationCode.Expiration
				)
			elif auth_token_type == "cookie":
				# Use client-defined expiration instead of AuthorizationCode.Expiration so that the session gets
				# extended properly at the introspection later
				# TODO: Revise this once cookies are moved to the token collection
				expiration = client_dict.get("session_expiration")
				new_session = await self.CookieService.create_cookie_client_session(
					root_session, client_id, requested_scope,
					nonce=nonce,
					redirect_uri=redirect_uri,
					tenants=[authorized_tenant] if authorized_tenant else None,
					requested_expiration=expiration
				)
				# Cookie flow implicitly redirects to the cookie entry point and puts the final redirect_uri in the query
				redirect_uri = await self._build_cookie_entry_redirect_uri(client_dict, redirect_uri)
			else:
				raise ValueError("Unexpected auth_token_type: {}".format(auth_token_type))

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
				authorized_tenant = await self.OpenIdConnectService.get_accessible_tenant_from_scope(
					requested_scope, anonymous_cid,
					has_access_to_all_tenants=self.OpenIdConnectService.RBACService.can_access_all_tenants(authz)
				)
			except exceptions.NoTenantsError:
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.NoTenants, client_id,
					redirect_uri=redirect_uri,
					state=state,
				)
			except exceptions.AccessDeniedError:
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.TenantAccessDenied, client_id,
					redirect_uri=redirect_uri,
					state=state,
				)

			if auth_token_type == "openid":
				new_session = await self.OpenIdConnectService.create_anonymous_oidc_session(
					anonymous_cid, client_dict, requested_scope,
					tenants=[authorized_tenant] if authorized_tenant else None,
					redirect_uri=redirect_uri,
					from_info=from_info,
				)
			elif auth_token_type == "cookie":
				new_session = await self.CookieService.create_anonymous_cookie_client_session(
					anonymous_cid, client_dict, requested_scope,
					tenants=[authorized_tenant] if authorized_tenant else None,
					redirect_uri=redirect_uri,
					from_info=from_info,
				)
				# Cookie flow implicitly redirects to the cookie entry point and puts the final redirect_uri in the query
				redirect_uri = await self._build_cookie_entry_redirect_uri(client_dict, redirect_uri)
			else:
				raise ValueError("Unexpected auth_token_type: {!r}".format(auth_token_type))

		AuditLogger.log(asab.LOG_NOTICE, "Authorization successful", struct_data={
			"psid": new_session.Session.ParentSessionId,
			"sid": new_session.SessionId,
			"cid": new_session.Credentials.Id,
			"t": [t for t in new_session.Authorization.Authz if t != "*"],
			"client_id": client_id,
			"anonymous": new_session.is_anonymous(),
			"from_ip": from_info,
			"scope": requested_scope,
		})
		await self.OpenIdConnectService.LastActivityService.update_last_activity(
			EventCode.AUTHORIZE_SUCCESS,
			credentials_id=new_session.Credentials.Id,
			tenants=[authorized_tenant] if authorized_tenant else None,
			scope=list(scope)
		)
		return await self.reply_with_successful_response(
			new_session, requested_scope, redirect_uri, state,
			code_challenge=code_challenge,
			code_challenge_method=code_challenge_method,
			from_info=from_info)

	async def _build_cookie_entry_redirect_uri(self, client_dict, redirect_uri):
		"""
		Get the client's configured cookie entry URI and extend it with relevant authorization parameters.
		"""
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


	async def _validate_client_options(self, client_id, redirect_uri, response_type):
		"""
		Verify that the requested authorization options comply with the client's configuration and permissions.
		"""
		try:
			client_dict = await self.OpenIdConnectService.ClientService.get(client_id)
		except KeyError as e:
			raise exceptions.ClientNotFoundError(client_id) from e

		try:
			await self.OpenIdConnectService.ClientService.validate_client_authorize_options(
				client=client_dict,
				redirect_uri=redirect_uri,
				response_type=response_type,
			)
		except exceptions.InvalidRedirectURI as e:
			raise e
		except exceptions.ClientError as e:
			L.error("Generic client error: {}".format(e), struct_data={"client_id": client_id})
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidRequest, client_id)
		return client_dict


	async def _get_auth_token_type(self, client_id, scope):
		"""
		Extract authorization type - either 'openid' or 'cookie'.
		"""
		if "openid" in scope:
			# OpenID Connect requests MUST contain the openid scope value.
			# Otherwise, the request is not considered OpenID and its behavior is unspecified
			if "cookie" in scope:
				L.error("Scope cannot contain 'openid' and 'cookie' at the same time.", struct_data={
					"scope": " ".join(scope)})
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.InvalidScope, client_id,
					error_description="Scope cannot contain 'openid' and 'cookie' at the same time.",
					struct_data={"scope": scope})
			return "openid"

		elif "cookie" in scope:
			return "cookie"

		else:
			L.error("Scope must contain 'openid' or 'cookie'.", struct_data={"scope": " ".join(scope)})
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidScope, client_id,
				error_description="Scope must contain 'openid' or 'cookie'.",
				struct_data={"scope": scope})

	async def _get_factors_to_setup(self, session):
		factors_to_setup = []

		# Check if all the enforced factors are present in the session
		if self.AuthenticationService.EnforceFactors is not None:
			factors_to_setup = list(self.AuthenticationService.EnforceFactors)
			for factor in session.Authentication.LoginFactors:
				if factor in factors_to_setup:
					factors_to_setup.remove(factor)

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
		code_challenge_method: str = None,
		from_info: list = None
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
		url_qs["code"] = await self.OpenIdConnectService.create_authorization_code(
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

		return aiohttp.web.HTTPFound(
			url,
			headers={
				# TODO: The server SHOULD generate a Location header field
				# https://httpwg.org/specs/rfc7231.html#status.302
				"Refresh": '0;url=' + url,
			},
			content_type="text/html",
			text="""<!doctype html>\n<html lang="en">\n<head></head><body>...</body>\n</html>\n"""
		)


	async def reply_with_redirect_to_login(
		self,
		client_id: str,
		response_type: str,
		scope: list,
		redirect_uri: str,
		**authorize_params
	):
		"""
		Reply with 404 and provide a link to the login form with a loopback to OIDC/authorize.
		Pass on the query parameters.
		"""
		# Get client collection
		client_dict = await self.OpenIdConnectService.ClientService.get(client_id)

		# Build redirect uri
		callback_uri = self.OpenIdConnectService.build_authorize_uri(
			client_dict=client_dict,
			client_id=client_id,
			response_type=response_type,
			scope=" ".join(scope),
			redirect_uri=redirect_uri,
			**authorize_params
		)

		# Build login uri
		login_query_params = [
			("redirect_uri", callback_uri),
			("client_id", client_id)]
		login_url = self._build_login_uri(client_dict, login_query_params)
		response = aiohttp.web.HTTPNotFound(
			headers={
				"Location": login_url,
				"Refresh": '0;url=' + login_url,
			},
			content_type="text/html",
			text="""<!doctype html>\n<html lang="en">\n<head></head><body>...</body>\n</html>\n"""
		)
		self.CookieService.delete_session_cookie(response)
		return response

	async def reply_with_factor_setup_redirect(
		self,
		missing_factors: list,
		client_id: str,
		response_type: str,
		scope: list,
		redirect_uri: str,
		**authorize_params
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
		client_dict = await self.OpenIdConnectService.ClientService.get(client_id)
		callback_uri = self.OpenIdConnectService.build_authorize_uri(
			client_dict=client_dict,
			client_id=client_id,
			response_type=response_type,
			scope=scope,
			redirect_uri=redirect_uri,
			**authorize_params
		)

		auth_url_params = [
			("setup", " ".join(missing_factors)),
			# Redirect URI needs an extra layer of percent-encoding when placed in fragment
			# because browsers automatically do one layer of decoding
			("redirect_uri", urllib.parse.quote(callback_uri))
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


	async def audit_authorize_error(self, error: OAuthAuthorizeError, access_ips: list = None):
		"""
		Append an authorization error entry to the audit.
		"""
		AuditLogger.log(asab.LOG_NOTICE, "Authorization failed", struct_data={
			"e": error.Error,
			"cid": error.CredentialsId,
			"client_id": error.ClientId,
			**error.StructData
		})


	def _build_login_uri(self, client_dict, login_query_params):
		"""
		Check if the client has a registered login URI. If not, use the default.
		Extend the URI with query parameters.
		"""
		login_uri = client_dict.get("login_uri")
		if login_uri is None:
			login_uri = "{}{}".format(self.AuthWebuiBaseUrl, self.LoginPath)

		if "#" in login_uri:
			# If the Login URI contains fragment, add the login params into the fragment query
			parsed = generic.urlparse(login_uri)
			fragment_parsed = generic.urlparse(parsed["fragment"])
			query = dict(urllib.parse.parse_qsl(fragment_parsed["query"]))
			query.update(login_query_params)
			fragment_parsed["query"] = urllib.parse.urlencode(query)
			parsed["fragment"] = generic.urlunparse(**fragment_parsed)
			return generic.urlunparse(**parsed)
		else:
			# If the Login URI contains no fragment, add the login params into the regular URL query
			return generic.update_url_query_params(login_uri, **dict(login_query_params))


	def _validate_request_parameters(self, request_parameters):
		"""
		Verify the presence of required parameters.

		As specified in OAuth 2.0 [RFC6749], Authorization Servers SHOULD ignore unrecognized request parameters.
		"""
		state = request_parameters.get("state") or None

		# Check for required parameters
		client_id = request_parameters.get("client_id") or None
		if client_id is None:
			L.error("Missing or empty required parameter: {}.".format("client_id"), struct_data=request_parameters)
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidRequest, client_id,
				redirect_uri=request_parameters.get("redirect_uri"),
				error_description="Missing or empty parameter {!r}.".format("client_id"),
				state=state,
				struct_data={"reason": "missing_query_parameter"})

		# NOTE: "redirect_uri" is required only by OIDC, not generic OAuth
		redirect_uri = request_parameters.get("redirect_uri") or None
		if redirect_uri is None:
			L.error("Missing or empty required parameter: {}.".format("redirect_uri"), struct_data=request_parameters)
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidRequest, client_id,
				redirect_uri=redirect_uri,
				error_description="Missing or empty parameter {!r}.".format("redirect_uri"),
				state=state,
				struct_data={"reason": "missing_query_parameter"})

		response_type = request_parameters.get("response_type") or None
		if response_type is None:
			L.error(
				"Missing or empty required parameter: {}.".format("response_type"), struct_data=request_parameters)
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.InvalidRequest, client_id,
				redirect_uri=redirect_uri,
				error_description="Missing or empty parameter {!r}.".format("response_type"),
				state=state,
				struct_data={"reason": "missing_query_parameter"})
		elif response_type != "code":
			L.error("Unsupported response type.", struct_data=request_parameters)
			raise OAuthAuthorizeError(
				AuthErrorResponseCode.UnsupportedResponseType, client_id,
				redirect_uri=redirect_uri,
				state=state)

		# NOTE: "scope" is required only by OIDC, not generic OAuth
		scope = request_parameters.get("scope") or None
		if scope is None:
			L.error("Missing or empty required parameter: {}.".format("scope"), struct_data=request_parameters)
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
				L.error("Unsupported prompt.", struct_data={"prompt": prompt})
				raise OAuthAuthorizeError(
					AuthErrorResponseCode.InvalidRequest, client_id,
					error_description="Invalid prompt value: {}".format(prompt),
					redirect_uri=redirect_uri,
					state=state)
			L.info("Prompt {!r} requested.".format(prompt))
