import logging
import typing

import aiohttp.web
import asab
import asab.web.rest
import asab.exceptions

from ...decorators import access_control
from ..service import ExternalLoginService
from ... import exceptions, generic, AuditLogger
from ..utils import AuthOperation
from ..exceptions import (
	ExternalAccountError,
	LoginWithExternalAccountError,
	SignupWithExternalAccountError,
	PairingExternalAccountError,
)

#

L = logging.getLogger(__name__)

#


class ExternalLoginPublicHandler(object):
	"""
	External login

	---
	tags: ["Public - External login"]
	"""

	def __init__(self, app, external_login_svc: ExternalLoginService):
		self.App = app
		self.ExternalLoginService = external_login_svc
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")

		web_app = app.WebContainer.WebApp
		web_app_public = app.PublicWebContainer.WebApp

		web_app.router.add_get("/public/ext-login/{provider_type}/pair", self.pair_external_account)
		web_app.router.add_get("/public/ext-login/{provider_type}/login", self.login_with_external_account)
		web_app.router.add_get("/public/ext-login/{provider_type}/signup", self.sign_up_with_external_account)
		web_app.router.add_get(self.ExternalLoginService.CallbackEndpointPath, self.external_auth_callback)

		web_app_public.router.add_get("/public/ext-login/{provider_type}/pair", self.pair_external_account)
		web_app_public.router.add_get("/public/ext-login/{provider_type}/login", self.login_with_external_account)
		web_app_public.router.add_get("/public/ext-login/{provider_type}/signup", self.sign_up_with_external_account)
		web_app_public.router.add_get(self.ExternalLoginService.CallbackEndpointPath, self.external_auth_callback)


	@access_control()
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
		client_id = self.ExternalLoginService.get_client_id(redirect_uri)
		if not await self.ExternalLoginService.validate_client_id_and_redirect_uri(redirect_uri, client_id):
			return aiohttp.web.HTTPBadRequest()
		authorization_url = await self.ExternalLoginService.initialize_pairing_external_account(
			provider_type, redirect_uri)
		return aiohttp.web.HTTPFound(authorization_url)


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
		client_id = self.ExternalLoginService.get_client_id(redirect_uri)
		if not await self.ExternalLoginService.validate_client_id_and_redirect_uri(redirect_uri, client_id):
			return aiohttp.web.HTTPBadRequest()
		authorization_url = await self.ExternalLoginService.initialize_login_with_external_account(
			provider_type, redirect_uri)
		return aiohttp.web.HTTPFound(authorization_url)


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
		client_id = self.ExternalLoginService.get_client_id(redirect_uri)
		if not await self.ExternalLoginService.validate_client_id_and_redirect_uri(redirect_uri, client_id):
			return aiohttp.web.HTTPBadRequest()
		try:
			authorization_url = await self.ExternalLoginService.initialize_signup_with_external_account(
				provider_type, redirect_uri)
		except exceptions.RegistrationNotOpenError:
			return aiohttp.web.HTTPNotFound()
		return aiohttp.web.HTTPFound(authorization_url)


	async def external_auth_callback(self, request):
		"""
		Finalize external account login, sign-up or pairing.
		Navigable endpoint, OAuth authorization callback. It must be registered as a redirect URI in OAuth app/client
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

		---
		parameters:
		-	name: code
			in: query
			description:
				OAuth authorization code.
			schema:
				type: string
		-	name: state
			in: query
			description:
				OAuth state variable.
			schema:
				type: string
		"""
		if request.method == "POST":
			authorization_data = dict(await request.post())
		else:
			authorization_data = dict(request.query)

		state = authorization_data["state"]
		operation = state[0]
		if operation == AuthOperation.LogIn:
			return await self._login_callback(request, authorization_data)
		elif operation == AuthOperation.SignUp:
			return await self._signup_callback(request, authorization_data)
		elif operation == AuthOperation.PairAccount:
			return await self._pair_account_callback(request, authorization_data)
		else:
			L.error("Cannot determine operation from state.", struct_data={"operation": operation})
			return aiohttp.web.HTTPBadRequest()


	async def _login_callback(self, request, authorization_data):
		access_ips = generic.get_request_access_ips(request)
		try:
			operation, new_sso_session, redirect_uri = await self.ExternalLoginService.finalize_login_with_external_account(
				session_context=request.Session, from_ip=access_ips, **authorization_data)
		except LoginWithExternalAccountError as e:
			AuditLogger.log(asab.LOG_NOTICE, "Authentication failed.", struct_data={
				"ext_provider_type": e.ProviderType,
				"subject_id": e.SubjectId,
				"from_ip": access_ips,
			})
			return self._error_redirect(e, result=e.Result)
		except SignupWithExternalAccountError as e:
			AuditLogger.log(asab.LOG_NOTICE, "Authentication failed.", struct_data={
				"ext_provider_type": e.ProviderType,
				"subject_id": e.SubjectId,
				"from_ip": access_ips,
			})
			return self._error_redirect(e, result=e.Result)

		if operation == AuthOperation.SignUp:
			result = "signup_success"
		else:
			assert operation == AuthOperation.LogIn
			result = "login_success"

		return self._success_response(redirect_uri, result=result, sso_session=new_sso_session)


	async def _signup_callback(self, request, authorization_data):
		access_ips = generic.get_request_access_ips(request)
		try:
			new_sso_session, redirect_uri = await self.ExternalLoginService.finalize_signup_with_external_account(
				session_context=request.Session, from_ip=access_ips, **authorization_data)
		except SignupWithExternalAccountError as e:
			AuditLogger.log(asab.LOG_NOTICE, "Sign-up failed.", struct_data={
				"ext_provider_type": e.ProviderType,
				"subject_id": e.SubjectId,
				"from_ip": access_ips,
			})
			return self._error_redirect(e, result=e.Result)

		return self._success_response(redirect_uri, result="signup_success", sso_session=new_sso_session)


	async def _pair_account_callback(self, request, authorization_data):
		access_ips = generic.get_request_access_ips(request)
		try:
			redirect_uri = await self.ExternalLoginService.finalize_pairing_external_account(
				session_context=request.Session, **authorization_data)
		except PairingExternalAccountError as e:
			L.log(asab.LOG_NOTICE, "Failed to pair external account.", struct_data={
				"ext_provider_type": e.ProviderType,
				"subject_id": e.SubjectId,
				"from_ip": access_ips,
			})
			return self._error_redirect(e, result=e.Result)

		return self._success_response(redirect_uri, result="pairing_success")


	def _error_redirect(self, error: typing.Optional[ExternalAccountError] = None, result: str = "error"):
		if not error:
			redirect_uri = generic.update_url_query_params(
				self.ExternalLoginService.DefaultRedirectUri,
				ext_login_result=result,
			)
		else:
			redirect_uri = generic.update_url_query_params(
				error.RedirectUri or self.ExternalLoginService.DefaultRedirectUri,
				ext_login_result=result,
			)
		response = aiohttp.web.HTTPNotFound(headers={
			"Location": redirect_uri,
			"Refresh": "0;url={}".format(redirect_uri),
		})
		return response


	def _success_response(self, redirect_uri: str, result: str, sso_session: typing.Optional = None):
		redirect_uri = generic.update_url_query_params(
			redirect_uri,
			ext_login_result=result,
		)
		response = aiohttp.web.HTTPFound(redirect_uri)
		if sso_session:
			self.ExternalLoginService.CookieService.set_session_cookie(
				response,
				cookie_value=sso_session.Cookie.Id,
				client_id=sso_session.OAuth2.ClientId
			)
		return response
