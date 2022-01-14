import logging
import urllib
import urllib.parse

import aiohttp
import aiohttp.web
import asab

from ...cookie.utils import set_cookie, delete_cookie

#

L = logging.getLogger(__name__)

#


class AuthorizeHandler(object):

	'''
	OpenID Connect Core 1.0
	https://openid.net/specs/openid-connect-core-1_0.html
	'''


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
		web_app.router.add_get('/openidconnect/authorize', self.authorize_get)
		web_app.router.add_post('/openidconnect/authorize', self.authorize_post)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get('/openidconnect/authorize', self.authorize_get)
		web_app_public.router.add_post('/openidconnect/authorize', self.authorize_post)


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
		'''
		https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

		3.1.2.1.  Authentication Request
		'''

		# Get the scope
		scope = request_parameters.get('scope')
		if scope is None:
			L.warning("Request doesn't specify any scope")
			return aiohttp.web.HTTPBadRequest()

		scope = frozenset(x.strip() for x in scope.split(' '))

		# Dispatch the request based on `response_type`
		# ... aka select the proper flow
		response_type = request_parameters.get('response_type')
		if response_type is None:
			L.warning("Request doesn't specify any response type")
			return aiohttp.web.HTTPBadRequest()

		# Authentication Code Flow
		elif response_type == 'code':
			return await self.authentication_code_flow(request, scope, request_parameters)

		L.warning("Unknown response type '{}' requested".format(response_type))
		return aiohttp.web.HTTPBadRequest()


	async def authentication_code_flow(self, request, scope, request_parameters):
		"""
		https://openid.net/specs/openid-connect-core-1_0.html

		Authentication Code Flow
		"""

		# OpenID Connect requests MUST contain the openid scope value.
		if 'openid' not in scope:
			L.warning("Scope does not contain 'openid'", struct_data={"scope": " ".join(scope), "headers": dict(request.headers)})
			return self.reply_with_authentication_error(request, request_parameters, "invalid_scope")

		redirect_uri = request_parameters.get('redirect_uri')
		if redirect_uri is None:
			L.warning("Redirect URI not specified", struct_data={
				"headers": dict(request.headers),
				"url": request.url
			})
			return self.reply_with_authentication_error(request, request_parameters, "invalid_request_uri")

		session = request.Session

		prompt = request_parameters.get("prompt")
		if prompt == "login":
			L.log(asab.LOG_NOTICE, "Login prompt requested", struct_data={
				"headers": dict(request.headers),
				"url": request.url
			})
			# If 'login' prompt is requested, delete the active session and re-authenticate anyway
			if session is not None:
				await self.SessionService.delete(session.SessionId)
				session = None

		if session is None and prompt == "none":
			# We are NOT authenticated, but login prompt is unwanted
			# TODO: The Authorization Server MUST NOT display any authentication or consent user interface pages.
			# An error is returned if an End-User is not already authenticated or the Client does not have
			#   pre-configured consent for the requested Claims
			#   or does not fulfill other conditions for processing the request.
			L.log(asab.LOG_NOTICE, "Not authenticated. No prompt requested.", struct_data={
				"headers": dict(request.headers),
				"url": request.url
			})
			return self.reply_with_authentication_error(request, request_parameters, "login_required")

		if session is None or prompt == "select_account":
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

			# Gather params which will be passed to the login page
			login_query_params = []

			# Gather params which will be passed to the after-login oidc/authorize call
			authorize_query_params = []

			for param, value in request_parameters.items():
				if param in {"ldid", "expiration"}:
					# Add session expiration
					# Add login descriptors (there may be multiple)
					login_query_params.append((param, value))
				if param in {"response_type", "scope", "client_id", "redirect_uri", "state"}:
					# Include all mandatory oidc/authorize params
					authorize_query_params.append((param, value))

			# Build the redirect URI back to this endpoint and add it to login params
			authorize_redirect_uri = "{}{}?{}".format(
				self.PublicApiBaseUrl,
				request.path,
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


		# We are authenticated !

		if session.OAuth2 is None:
			L.warning("The session has not been created with OpenId/OAuth2 in scope.")
			return self.reply_with_authentication_error(request, request_parameters, "access_denied")

		# TODO: Authorize the access to a given resource (specified by redirect_uri and scope )

		# TODO: replace with ABAC
		#  (the policies can use oidc client-id and scope)

		# Redirect to factor management page if (re)set of any factor is required
		factors_to_setup = await self._get_factors_to_setup(session)

		if len(factors_to_setup) > 0:
			L.warning(
				"Auth factor setup required. Redirecting to setup.",
				struct_data={"missing_factors": " ".join(factors_to_setup), "cid": session.CredentialsId}
			)
			return await self.reply_with_factor_setup_redirect(
				request, scope, request_parameters, session, factors_to_setup
			)

		return await self.reply_with_successful_response(request, scope, request_parameters, session)


	async def _get_factors_to_setup(self, session):
		factors_to_setup = []

		# Check if all the enforced factors are present in the session
		if self.AuthenticationService.EnforceFactors is not None:
			factors_to_setup = list(self.AuthenticationService.EnforceFactors)
			for factor in session.LoginDescriptor["factors"]:
				if factor["type"] in factors_to_setup:
					factors_to_setup.remove(factor["type"])

		# Check if there are additional factors to be reset
		credentials = await self.CredentialsService.get(session.CredentialsId)
		cred_enforce_factors = set(credentials.get("enforce_factors", []))
		for factor in cred_enforce_factors:
			if factor not in factors_to_setup:
				factors_to_setup.append(factor)

		return factors_to_setup


	async def reply_with_successful_response(self, request, scope, request_parameters, session):
		"""
		https://openid.net/specs/openid-connect-core-1_0.html
		3.1.2.5.  Successful Authentication Response

		The OAuth 2.0 Authorization Framework
		https://tools.ietf.org/html/rfc6749#section-4.1.2
		4.1.2.  Authorization Response
		"""

		# Prepare the redirect URL
		url = urllib.parse.urlparse(request_parameters['redirect_uri'])
		url_qs = urllib.parse.parse_qs(url.query)

		if len(request_parameters.get('state', [])) > 0:
			# The OAuth 2.0 Authorization Framework, 4.1.2.  Authorization Response
			# If the "state" parameter was present in the client authorization request,
			# then use the exact value received from the client.
			url_qs["state"] = request_parameters['state']

		# Add the Authorization Code into the session ...
		if "cookie" not in scope:
			url_qs["code"] = self.OpenIdConnectService.generate_authotization_code(session.SessionId)

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

		if 'cookie' in request_parameters['scope']:
			set_cookie(self.App, response, session)

		return response


	async def reply_with_factor_setup_redirect(self, request, scope, request_parameters, session, missing_factors):
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
			("prompt", "login")
		]

		for param, value in request_parameters.items():
			if param in {"response_type", "scope", "client_id", "redirect_uri", "state"}:
				# Include all mandatory oidc/authorize params
				authorize_query_params.append((param, value))

		# Build the redirect URI back to this endpoint and add it to auth URL params
		authorize_redirect_uri = "{}{}?{}".format(
			self.PublicApiBaseUrl,
			request.path,
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

		if "cookie" in request_parameters["scope"]:
			set_cookie(self.App, response, session)

		return response


	def reply_with_authentication_error(self, request, request_parameters, error: str):
		"""
		3.1.2.6.  Authentication Error Response
		"""
		qs = request_parameters.copy()
		qs['error'] = error
		qs_encoded = urllib.parse.urlencode(qs)

		if self.PublicApiBaseUrl is not None:
			redirect = "{public_base_url}{path}?{qs}".format(
				public_base_url=self.PublicApiBaseUrl,
				path=request.path,
				qs=qs_encoded
			)
		else:
			redirect = "{scheme}://{host}{path}?{qs}".format(
				scheme=request.scheme,
				host=request.host,
				path=request.path,
				qs=qs_encoded
			)

		return aiohttp.web.HTTPFound(redirect)
