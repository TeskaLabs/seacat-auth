import logging
import urllib
import urllib.parse

import aiohttp
import aiohttp.web
import asab

from ...cookie.utils import set_cookie, delete_cookie
from ...client import exceptions

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
			if parameter not in request_parameters:
				L.warning("Missing required parameter: {}".format(parameter), struct_data=request_parameters)
				return self.reply_with_authentication_error(
					request,
					request_parameters,
					"invalid_request",
					"Missing required parameter: {}".format(parameter),
				)
		if "tenant" not in request_parameters:
			# TODO: Respond with error
			L.warning("Missing required parameter: {}".format("tenant"), struct_data=request_parameters)

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
				tenant=request_parameters.get("tenant"),
				client_secret=request_parameters.get("client_secret"),
				state=request_parameters.get("state"),
				prompt=request_parameters.get("prompt"),
				login_parameters=login_parameters
			)

		L.warning("Unknown response type: {}".format(response_type))
		return self.reply_with_authentication_error(
			request_parameters,
			"invalid_request",
			"Invalid response_type: {}".format(response_type),
		)


	async def authentication_code_flow(
		self,
		request,
		scope: list,
		client_id: str,
		redirect_uri: str,
		tenant: str,
		client_secret: str = None,
		state: str = None,
		prompt: str = None,
		login_parameters: dict = None,
	):
		"""
		https://openid.net/specs/openid-connect-core-1_0.html

		Authentication Code Flow
		"""

		try:
			await self.OpenIdConnectService.ClientService.authorize_client(
				client_id=client_id,
				client_secret=client_secret,
				redirect_uri=redirect_uri,
				scope=scope,
			)
		# TODO: Fail with error response if client authorization fails
		except KeyError:
			L.info("Client ID not found", struct_data={"client_id": client_id})
			# return self.reply_with_authentication_error(request, request_parameters, "invalid_client_id")
		except exceptions.InvalidClientSecret as e:
			L.info(str(e), struct_data={"client_id": client_id})
			# return self.reply_with_authentication_error(request, request_parameters, "unauthorized_client")
		except exceptions.InvalidRedirectURI as e:
			L.error(str(e), struct_data={"client_id": client_id, "redirect_uri": e.RedirectURI})
			return self.reply_with_authentication_error(
				"invalid_redirect_uri",
				redirect_uri=None,
				error_description="redirect_uri is not valid for given client_id",
				state=state
			)
		except exceptions.ClientError as e:
			L.info(str(e), struct_data={"client_id": client_id})
			# return self.reply_with_authentication_error(request, request_parameters, "unauthorized_client")

		# OpenID Connect requests MUST contain the openid scope value.
		if "openid" not in scope:
			L.warning("Scope does not contain 'openid'", struct_data={"scope": " ".join(scope)})
			return self.reply_with_authentication_error(
				"invalid_scope",
				redirect_uri,
				error_description="Scope must contain 'openid'",
				state=state
			)

		root_session = request.Session

		# Only root sessions can be used to obtain auth code
		if root_session is not None and root_session.Session.Type != "root":
			L.warning("Session type must be 'root'", struct_data={"session_type": root_session.Session.Type})
			root_session = None

		if prompt not in frozenset([None, "none", "login", "select_account"]):
			L.warning("Invalid parameter value for prompt", struct_data={"prompt": prompt})
			return self.reply_with_authentication_error(
				"invalid_request",
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
			return self.reply_with_authentication_error(
				request,
				"login_required",
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
				scope=scope, client_id=client_id,
				redirect_uri=redirect_uri,
				state=state,
				login_parameters=login_parameters)

		# We are authenticated!

		# Check if requested tenant is accessible to the user
		if tenant is not None:
			if tenant not in await self.OpenIdConnectService.TenantService.get_tenants(root_session.Credentials.Id):
				return self.reply_with_authentication_error(
					"access_denied",
					redirect_uri,
					state=state,
					error_description="Unauthorized tenant",
				)

		# TODO: Authorize the access to a given resource (specified by redirect_uri and scope )

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
				root_session, factors_to_setup,
				"code", scope, client_id, redirect_uri, state, login_parameters
			)

		requested_expiration = login_parameters.get("expiration")
		if requested_expiration is not None:
			requested_expiration = int(requested_expiration)

		# TODO: Create a new child session with the requested scope
		session = await self.OpenIdConnectService.create_oidc_session(
			root_session, client_id, scope, tenant, requested_expiration)

		return await self.reply_with_successful_response(session, scope, redirect_uri, tenant, state)


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
		tenant: str = None,
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

		# TODO: Include tenant?
		if tenant is not None:
			url_qs["tenant"] = tenant

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
			url.fragment
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

		if 'cookie' in scope:
			set_cookie(self.App, response, session)

		return response


	async def reply_with_redirect_to_login(
		self, response_type: str, scope: list, client_id: str, redirect_uri: str,
		state: str = None,
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

		# Build the redirect URI back to this endpoint and add it to login params
		authorize_redirect_uri = "{}{}?{}".format(
			self.PublicApiBaseUrl,
			self.AuthorizePath,
			urllib.parse.urlencode(authorize_query_params)
		)

		login_query_params.append(("redirect_uri", authorize_redirect_uri))

		login_url = "{}{}?{}".format(
			self.AuthWebuiBaseUrl,
			self.LoginPath,
			urllib.parse.urlencode(login_query_params)
		)
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

		if "cookie" in scope:
			set_cookie(self.App, response, session)

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

		response_qs = urllib.parse.urlencode(qs)

		if redirect_uri is not None:
			# Redirect to redirect_uri
			redirect_uri_qs = urllib.parse.urlparse(redirect_uri).query
			if len(redirect_uri_qs) > 0:
				response_qs = "{}&{}".format(redirect_uri_qs, response_qs)
			redirect = "{redirect_uri}?{qs}".format(
				redirect_uri=redirect_uri,
				qs=response_qs
			)
		else:
			# TODO: Use the /message page on frontend
			redirect = "{public_base_url}{path}?{qs}".format(
				public_base_url=self.PublicApiBaseUrl,
				path=self.AuthorizePath,
				qs=response_qs
			)

		return aiohttp.web.HTTPFound(redirect)
