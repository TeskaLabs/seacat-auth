import logging
import typing
import aiohttp.web
import asab
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.exceptions

from ... import exceptions, generic, AuditLogger
from .service import ExternalAuthenticationService
from .utils import AuthOperation
from ..exceptions import (
	ExternalAccountError,
	LoginWithExternalAccountError,
	SignupWithExternalAccountError,
	PairingExternalAccountError,
)


L = logging.getLogger(__name__)


class ExternalAuthenticationHandler(object):
	"""
	External login

	---
	tags: ["Public - External login"]
	"""

	def __init__(self, app, external_authentication_svc: ExternalAuthenticationService):
		self.App = app
		self.ExternalAuthenticationService = external_authentication_svc
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")

		web_app = app.WebContainer.WebApp
		web_app_public = app.PublicWebContainer.WebApp

		web_app.router.add_get("/public/ext-login/{provider_type}/pair", self.pair_external_account)
		web_app.router.add_get("/public/ext-login/{provider_type}/login", self.login_with_external_account)
		web_app.router.add_get("/public/ext-login/{provider_type}/signup", self.sign_up_with_external_account)
		web_app.router.add_get(self.ExternalAuthenticationService.CallbackEndpointPath, self.external_auth_callback)
		web_app.router.add_post(self.ExternalAuthenticationService.CallbackEndpointPath, self.external_auth_callback)

		web_app_public.router.add_get("/public/ext-login/{provider_type}/pair", self.pair_external_account)
		web_app_public.router.add_get("/public/ext-login/{provider_type}/login", self.login_with_external_account)
		web_app_public.router.add_get("/public/ext-login/{provider_type}/signup", self.sign_up_with_external_account)
		web_app_public.router.add_get(self.ExternalAuthenticationService.CallbackEndpointPath, self.external_auth_callback)
		web_app_public.router.add_post(self.ExternalAuthenticationService.CallbackEndpointPath, self.external_auth_callback)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.noauth  # Uses cookie authentication
	async def pair_external_account(self, request):
		"""
		Initialize pairing an external account with the current user's credentials.
		Navigable endpoint, redirects to external login page.

		---
		parameters:
		-	name: redirect_uri
			in: query
			description:
				Where to redirect the user after successful login.
			schema:
				type: string
		"""
		redirect_uri = request.query.get("redirect_uri")
		provider_type = request.match_info["provider_type"]
		return await self.ExternalAuthenticationService.initialize_pairing_with_ext_provider(
			provider_type, redirect_uri)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.noauth  # Uses cookie authentication, expects logged-out user
	async def login_with_external_account(self, request):
		"""
		Initialize login with external account.
		Navigable endpoint, redirects to external login page.
		Can also be used as entrypoint for sign-up:
		When the external account is unknown and sign-up is enabled, Seacat Auth attempts to sign up.

		---
		parameters:
		-	name: redirect_uri
			in: query
			description:
				Where to redirect the user after successful login.
			schema:
				type: string
		"""
		redirect_uri = request.query.get("redirect_uri")
		provider_type = request.match_info["provider_type"]
		return await self.ExternalAuthenticationService.initialize_login_with_ext_provider(
			provider_type, redirect_uri)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.noauth  # Uses cookie authentication, expects logged-out user
	async def sign_up_with_external_account(self, request):
		"""
		Initialize sign up with external account.
		Navigable endpoint, redirects to external login page.

		---
		parameters:
		-	name: redirect_uri
			in: query
			description:
				Where to redirect the user after successful login.
			schema:
				type: string
		"""
		redirect_uri = request.query.get("redirect_uri")
		provider_type = request.match_info["provider_type"]
		try:
			return await self.ExternalAuthenticationService.initialize_signup_with_ext_provider(
				provider_type, redirect_uri)
		except exceptions.RegistrationNotOpenError:
			return aiohttp.web.HTTPNotFound()


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.noauth  # Uses cookie authentication, expects logged-out user
	async def external_auth_callback(self, request):
		"""
		Finalize external account login, sign-up or pairing.
		Navigable endpoint, OAuth2/SAML authorization callback. It must be registered as a redirect URI in app/client
		settings at the external account provider.
		Finishes with redirect to the URL specified at the external auth entrypoint,
		appending `ext_login_result` to the URL query.
		Defined `ext_login_result` values:
			- `login_success`: User logged in successfully with external account.
			- `signup_success`: User was signed up and logged in successfully with external account.
			- `pairing_success`: External account successfully paired with current user's credentials.
			- `login_error`: Logging in with external account failed.
			- `signup_error`: Signing up with external account failed.
			- `pairing_error`: Pairing external account to current user's credentials failed.
		"""
		access_ips = generic.get_request_access_ips(request)

		if request.method == "POST":
			payload = dict(await request.post())
		elif request.method == "GET":
			payload = dict(request.query)
		else:
			raise RuntimeError("Unsupported request method {!r}".format(request.method))

		try:
			operation_code, new_sso_session, redirect_uri = (
				await self.ExternalAuthenticationService.process_external_auth_callback(request, payload))
		except LoginWithExternalAccountError as e:
			AuditLogger.log(asab.LOG_NOTICE, "External account authentication failed.", struct_data={
				"ext_provider_type": e.ProviderType,
				"subject_id": e.SubjectId,
				"from_ip": access_ips,
			})
			return self._error_redirect(e)
		except SignupWithExternalAccountError as e:
			AuditLogger.log(asab.LOG_NOTICE, "External account sign-up failed.", struct_data={
				"ext_provider_type": e.ProviderType,
				"subject_id": e.SubjectId,
				"from_ip": access_ips,
			})
			return self._error_redirect(e)
		except PairingExternalAccountError as e:
			L.log(asab.LOG_NOTICE, "External account pairing failed.", struct_data={
				"ext_provider_type": e.ProviderType,
				"subject_id": e.SubjectId,
				"from_ip": access_ips,
			})
			return self._error_redirect(e)

		return self._success_response(redirect_uri, operation_code, sso_session=new_sso_session)


	def _error_redirect(self, error: typing.Optional[ExternalAccountError] = None):
		result = error.Result
		if error and error.RedirectUri:
			redirect_uri = error.RedirectUri
		else:
			redirect_uri = self.ExternalAuthenticationService.DefaultRedirectUri

		error_params = {"ext_login_result": result}
		if error.ErrorDetail:
			error_params["ext_login_error"] = error.ErrorDetail

		if "#" in redirect_uri:
			# URI contains fragment, add the result to the fragment
			# (some apps use fragment for client-side routing and state)
			base, fragment = redirect_uri.split("#", 1)
			fragment = generic.update_url_query_params(fragment, **error_params)
			redirect_uri = "{}#{}".format(base, fragment)
		else:
			redirect_uri = generic.update_url_query_params(redirect_uri, **error_params)

		response = aiohttp.web.HTTPNotFound(headers={
			"Location": redirect_uri,
			"Refresh": "0;url={}".format(redirect_uri),
		})
		return response


	def _success_response(self, redirect_uri: str, operation_code: AuthOperation, sso_session: typing.Optional = None):
		match operation_code:
			case AuthOperation.LogIn:
				result_msg = "login_success"
			case AuthOperation.SignUp:
				result_msg = "signup_success"
			case AuthOperation.PairAccount:
				result_msg = "pairing_success"
			case _:
				raise ValueError("Unknown operation code {!r}".format(operation_code))

		if "#" in redirect_uri:
			# URI contains fragment, add the result to the fragment
			# (some apps use fragment for client-side routing and state)
			base, fragment = redirect_uri.split("#", 1)
			fragment = generic.update_url_query_params(
				fragment,
				ext_login_result=result_msg,
			)
			redirect_uri = "{}#{}".format(base, fragment)
		else:
			redirect_uri = generic.update_url_query_params(
				redirect_uri,
				ext_login_result=result_msg,
			)

		response = aiohttp.web.HTTPFound(redirect_uri)
		if sso_session:
			self.ExternalAuthenticationService.CookieService.set_session_cookie(
				response,
				cookie_value=sso_session.Cookie.Id,
				client_id=sso_session.OAuth2.ClientId
			)
		return response
