import logging
import urllib
import urllib.parse

import aiohttp
import aiohttp.web
import asab

from ...audit import AuditCode
from ...cookie.utils import delete_cookie, set_cookie
from ... import client
from ... import exceptions
from ..utils import AuthErrorResponseCode
from ..pkce import InvalidCodeChallengeMethodError
from ...generic import urlparse, urlunparse

#

L = logging.getLogger(__name__)

#


class AuthorizeHandler(object):

	'''
	OpenID Connect Core 1.0
	https://openid.net/specs/openid-connect-core-1_0.html
	'''
	AuthorizePath = "/openidconnect/authorize"

	def __init__(self, app, oidc_svc, credentials_svc, public_api_base_url, auth_webui_base_url):
		self.App = app
		self.SessionService = app.get_service('seacatauth.SessionService')
		self.CookieService = app.get_service('seacatauth.CookieService')
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
		'''
		https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

		3.1.2.1.  Authentication Request

		If using the HTTP GET method, the request parameters are serialized using URI Query String Serialization
		'''
		return await self.authorize(request, request.query)


	async def authorize_post(self, request):
		'''
		https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

		3.1.2.1.  Authentication Request

		If using the HTTP POST method, the request parameters are serialized using Form Serialization
		'''
		request_parameters = await request.post()
		return await self.authorize(request, request_parameters)


	async def authorize(self, request, request_parameters):
		"""
		https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

		3.1.2.1.  Authentication Request
		"""

		# Check the presence of required parameters
		for parameter in frozenset(["scope", "client_id", "response_type", "redirect_uri"]):
			if parameter not in request_parameters or len(request_parameters[parameter]) == 0:
				L.warning("Missing required parameter: {}".format(parameter), struct_data=request_parameters)
				return self.reply_with_authentication_error(
					AuthErrorResponseCode.InvalidRequest,
					request_parameters.get("redirect_uri") or None,
					error_description="Missing required parameter: {}".format(parameter),
					state=request_parameters.get("state")
				)

		# Select the proper flow based on response_type
		response_type = request_parameters["response_type"]

		# Check non-standard authorize parameters
		# TODO: Move these parameters to client configuration instead
		login_parameters = {}
		for parameter in ["ldid", "expiration"]:
			if parameter in request_parameters:
				L.info("Using a non-standard authorize parameter '{}'.".format(parameter))
				login_parameters[parameter] = request_parameters[parameter]

		# Authentication Code Flow
		if response_type == "code":
			return await self.authentication_code_flow(
				request,
				scope=request_parameters["scope"].split(" "),
				client_id=request_parameters["client_id"],
				redirect_uri=request_parameters["redirect_uri"],
				client_secret=request_parameters.get("client_secret"),
				state=request_parameters.get("state"),
				prompt=request_parameters.get("prompt"),
				code_challenge=request_parameters.get("code_challenge"),
				code_challenge_method=request_parameters.get("code_challenge_method"),
				login_parameters=login_parameters
			)

		message = "Unsupported response type: {}".format(response_type)
		L.warning(message)
		await self.audit_authorize_error(
			request_parameters["client_id"],
			AuthErrorResponseCode.UnsupportedResponseType,
			response_type=response_type
		)
		return self.reply_with_authentication_error(
			request_parameters,
			AuthErrorResponseCode.UnsupportedResponseType,
			message,
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
			client_dict = await self.OpenIdConnectService.ClientService.get(client_id)
		except KeyError:
			L.error("Client ID not found", struct_data={"client_id": client_id})
			return self.reply_with_authentication_error(
				AuthErrorResponseCode.InvalidRequest,
				redirect_uri,
				error_description="Invalid client_id",
				state=state
			)
		try:
			await self.OpenIdConnectService.ClientService.authorize_client(
				client=client_dict,
				client_secret=client_secret,
				redirect_uri=redirect_uri,
				scope=scope,
				response_type="code",
			)
		except client.exceptions.InvalidClientSecret:
			L.error("Invalid client secret", struct_data={"client_id": client_id})
			return self.reply_with_authentication_error(
				AuthErrorResponseCode.UnauthorizedClient,
				redirect_uri,
				error_description="Unauthorized client",
				state=state
			)
		# TODO: Check for invalid redirect URI
		except client.exceptions.ClientError as e:
			L.error("Generic client error: {}".format(e), struct_data={"client_id": client_id})
			await self.audit_authorize_error(
				client_id, "client_error",
				redirect_uri=redirect_uri,
			)
			return self.reply_with_authentication_error(
				AuthErrorResponseCode.InvalidRequest,
				redirect_uri=redirect_uri,
				error_description="Client error.",
				state=state
			)

		if code_challenge is not None:
			if code_challenge_method is None:
				code_challenge_method = self.OpenIdConnectService.PKCE.DefaultCodeChallengeMethod
			try:
				self.OpenIdConnectService.PKCE.validate_code_challenge_method(client_dict, code_challenge_method)
			except InvalidCodeChallengeMethodError:
				L.error("Invalid code challenge method.", struct_data={
					"client_id": client_id, "method": code_challenge_method})
				await self.audit_authorize_error(
					client_id, "client_error",
					redirect_uri=redirect_uri,
				)
				return self.reply_with_authentication_error(
					AuthErrorResponseCode.InvalidRequest,
					redirect_uri=redirect_uri,
					error_description="Client error.",
					state=state
				)

		# OpenID Connect requests MUST contain the openid scope value.
		# Otherwise, the request is not considered OpenID and its behavior is unspecified
		if "openid" not in scope:
			L.warning("Scope does not contain 'openid'", struct_data={"scope": " ".join(scope)})
			await self.audit_authorize_error(
				client_id, "invalid_scope",
				scope=scope,
			)
			return self.reply_with_authentication_error(
				AuthErrorResponseCode.InvalidScope,
				redirect_uri,
				error_description="Scope must contain 'openid'",
				state=state
			)

		root_session = request.Session

		# Only root sessions can be used to authorize client sessions
		if root_session is not None:
			if root_session.Session.Type != "root":
				L.warning("Session type must be 'root'", struct_data={"sid": root_session.Id, "type": root_session.Session.Type})
				root_session = None
			elif root_session.Authentication.IsAnonymous:
				L.warning("Cannot authorize with anonymous session", struct_data={"sid": root_session.Id})
				root_session = None

		if prompt not in frozenset([None, "none", "login", "select_account"]):
			L.warning("Invalid parameter value for prompt", struct_data={"prompt": prompt})
			await self.audit_authorize_error(
				client_id, "invalid_request",
				prompt=prompt,
			)
			return self.reply_with_authentication_error(
				AuthErrorResponseCode.InvalidRequest,
				redirect_uri,
				error_description="Invalid parameter value for prompt: {}".format(prompt),
				state=state
			)

		if prompt == "login":
			L.log(asab.LOG_NOTICE, "Login prompt requested", struct_data={
				"headers": dict(request.headers),
				"url": request.url
			})
			# If 'login' prompt is requested, delete the active session and re-authenticate anyway
			if root_session is not None:
				await self.SessionService.delete(root_session.SessionId)
				root_session = None

		if root_session is None and prompt == "none":
			# We are NOT authenticated, but login prompt is unwanted
			# TODO: The Authorization Server MUST NOT display any authentication or consent user interface pages.
			# An error is returned if an End-User is not already authenticated or the Client does not have
			#   pre-configured consent for the requested Claims
			#   or does not fulfill other conditions for processing the request.
			L.log(asab.LOG_NOTICE, "Not authenticated. No prompt requested.", struct_data={
				"headers": dict(request.headers),
				"url": request.url
			})
			await self.audit_authorize_error(
				client_id, "login_required",
				prompt=prompt,
			)
			return self.reply_with_authentication_error(
				request,
				AuthErrorResponseCode.LoginRequired,
				redirect_uri,
				state=state
			)

		if root_session is None or prompt == "select_account":
			# We are NOT authenticated or the user is switching accounts
			#   >> Redirect to login and then back to this endpoint

			# If 'select_account' prompt is requested, re-authenticate without deleting the session
			# TODO: Implement proper multi-account session management
			if prompt == "select_account":
				L.log(asab.LOG_NOTICE, "Account selection prompt requested", struct_data={
					"headers": dict(request.headers),
					"url": request.url
				})

			# We are not authenticated, show 404 and provide the link to the login form
			return await self.reply_with_redirect_to_login(
				response_type="code",
				scope=scope,
				client_id=client_id,
				redirect_uri=redirect_uri,
				state=state,
				code_challenge=code_challenge,
				code_challenge_method=code_challenge_method,
				login_parameters=login_parameters)

		# We are authenticated!

		# Authorize access to tenants by scope
		try:
			tenants = await self.authorize_tenants_by_scope(scope, root_session, client_id)
		except exceptions.AccessDeniedError:
			return self.reply_with_authentication_error(
				AuthErrorResponseCode.AccessDenied,
				redirect_uri,
				state=state,
			)

		# TODO: replace with ABAC
		#  (the policies can use oidc client-id and scope)

		# Redirect to factor management page if (re)set of any factor is required
		# TODO: Move this check to AuthenticationService.login, add "restricted" flag
		factors_to_setup = await self._get_factors_to_setup(root_session)

		if len(factors_to_setup) > 0:
			L.warning(
				"Auth factor setup required. Redirecting to setup.",
				struct_data={"missing_factors": " ".join(factors_to_setup), "cid": root_session.Credentials.Id}
			)
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

		requested_expiration = login_parameters.get("expiration")
		if requested_expiration is not None:
			requested_expiration = int(requested_expiration)

		if "cookie" in scope:
			session = await self.CookieService.create_cookie_client_session(
				root_session, client_id, scope, tenants, requested_expiration)
		else:
			session = await self.OpenIdConnectService.create_oidc_session(
				root_session, client_id, scope, tenants, requested_expiration,
				code_challenge=code_challenge,
				code_challenge_method=code_challenge_method)

		await self.audit_authorize_success(session)
		return await self.reply_with_successful_response(session, scope, redirect_uri, state)


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
		state: str = None
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

		# Add the Authorization Code into the session ...
		if "cookie" not in scope:
			url_qs["code"] = await self.OpenIdConnectService.generate_authorization_code(session.SessionId)

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

		if "cookie" in scope:
			# TODO: Check that the cookie domain matches
			#   Setting cookies for mismatching domains is a security flaw
			set_cookie(self.App, response, session)

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
		authorize_query_params = [
			("response_type", response_type),
			("scope", " ".join(scope)),
			("client_id", client_id),
			("redirect_uri", redirect_uri),
		]
		if state is not None:
			authorize_query_params.append(("state", state))
		if code_challenge is not None:
			authorize_query_params.append(("code_challenge", code_challenge))
		if code_challenge_method is not None:
			authorize_query_params.append(("code_challenge_method", code_challenge_method))

		# Build the redirect URI back to this endpoint and add it to login params
		authorize_redirect_uri = "{}{}?{}".format(
			self.PublicApiBaseUrl,
			self.AuthorizePath,
			urllib.parse.urlencode(authorize_query_params)
		)

		login_query_params.append(("redirect_uri", authorize_redirect_uri))
		login_query_params.append(("client_id", client_id))

		login_url = await self._build_login_uri(client_id, login_query_params)
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
			# TODO: Use the /message page on frontend
			redirect = "{public_base_url}{path}?{qs}".format(
				public_base_url=self.PublicApiBaseUrl,
				path=self.AuthorizePath,
				qs=urllib.parse.urlencode(qs)
			)
		return aiohttp.web.HTTPFound(redirect)


	async def audit_authorize_success(self, session):
		await self.OpenIdConnectService.AuditService.append(AuditCode.AUTHORIZE_SUCCESS, {
			"cid": session.Credentials.Id,
			"tenants": [t for t in session.Authorization.Authz if t != "*"],
			"client_id": session.OAuth2.ClientId,
			"scope": session.OAuth2.Scope,
		})


	async def audit_authorize_error(self, client_id, error, credential_id=None, **kwargs):
		d = {
			"client_id": client_id,
			"error": error,
			**kwargs
		}
		if credential_id is not None:
			d["cid"] = credential_id
		await self.OpenIdConnectService.AuditService.append(AuditCode.AUTHORIZE_ERROR, d)


	async def authorize_tenants_by_scope(self, scope, session, client_id):
		has_access_to_all_tenants = self.OpenIdConnectService.RBACService.has_resource_access(
			session.Authorization.Authz, tenant=None, requested_resources=["authz:superuser"]) \
			or self.OpenIdConnectService.RBACService.has_resource_access(
			session.Authorization.Authz, tenant=None, requested_resources=["authz:tenant:access"])
		try:
			tenants = await self.OpenIdConnectService.TenantService.get_tenants_by_scope(
				scope, session.Credentials.Id, has_access_to_all_tenants)
		except exceptions.TenantNotFoundError as e:
			L.error("Tenant not found", struct_data={"tenant": e.Tenant})
			await self.audit_authorize_error(
				client_id, "access_denied:tenant_not_found",
				credential_id=session.Credentials.Id,
				tenant=e.Tenant,
				scope=scope
			)
			raise exceptions.AccessDeniedError(subject=session.Credentials.Id)
		except exceptions.TenantAccessDeniedError as e:
			L.error("Tenant access denied", struct_data={"tenant": e.Tenant, "cid": session.Credentials.Id})
			await self.audit_authorize_error(
				client_id, "access_denied:unauthorized_tenant",
				credential_id=session.Credentials.Id,
				tenant=e.Tenant,
				scope=scope
			)
			raise exceptions.AccessDeniedError(subject=session.Credentials.Id)
		except exceptions.NoTenantsError:
			L.error("Tenant access denied", struct_data={"cid": session.Credentials.Id})
			await self.audit_authorize_error(
				client_id, "access_denied:user_has_no_tenant",
				credential_id=session.Credentials.Id,
				scope=scope
			)
			raise exceptions.AccessDeniedError(subject=session.Credentials.Id)

		return tenants


	async def _build_login_uri(self, client_id, login_query_params):
		"""
		Check if the client has a registered login URI. If not, use the default.
		Extend the URI with query parameters.
		"""
		try:
			client_dict = await self.OpenIdConnectService.ClientService.get(client_id)
			client_login_uri = client_dict.get("login_uri")
		except KeyError:
			client_login_uri = None
		if client_login_uri is not None:
			parsed = urlparse(client_login_uri)
			query = urllib.parse.parse_qs(parsed["query"])
			# WARNING: If the client's login URI includes query parameters with the same names
			# as those used by Seacat Auth, they will be overwritten
			query.update(login_query_params)
			parsed["query"] = urllib.parse.urlencode(query)
			login_url = urlunparse(**parsed)
		else:
			# Seacat Auth login expects the parameters to be at the end of the URL (in the fragment (hash) part)
			# TODO: Consider using regular query parameters instead (UI refactoring needed)
			#   so that Seacat Auth UI does not need a special approach here
			login_url = "{}{}?{}".format(
				self.AuthWebuiBaseUrl,
				self.LoginPath,
				urllib.parse.urlencode(login_query_params)
			)
		return login_url
