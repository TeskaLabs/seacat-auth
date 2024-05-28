import logging

import aiohttp.web
import asab
import asab.web.rest
import asab.exceptions

from ...decorators import access_control
from ..service import ExternalLoginService
from ... import exceptions, generic, AuditLogger
from ..utils import AuthOperation
from ..exceptions import (
	ExternalLoginError,
	ExternalAccountAlreadyUsedError,
	ExternalAccountNotFoundError,
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

		web_app.router.add_get("/public/ext-login/{provider_type}/add", self.add_external_account)
		web_app.router.add_get("/public/ext-login/{provider_type}/login", self.login_with_external_account)
		web_app.router.add_get("/public/ext-login/{provider_type}/signup", self.sign_up_with_external_account)
		web_app.router.add_get(self.ExternalLoginService.CallbackEndpointPath, self.external_auth_callback)

		web_app_public.router.add_get("/public/ext-login/{provider_type}/add", self.add_external_account)
		web_app_public.router.add_get("/public/ext-login/{provider_type}/login", self.login_with_external_account)
		web_app_public.router.add_get("/public/ext-login/{provider_type}/signup", self.sign_up_with_external_account)
		web_app_public.router.add_get(self.ExternalLoginService.CallbackEndpointPath, self.external_auth_callback)


	@access_control()
	async def add_external_account(self, request):
		"""
		Initialize adding an external account into the current user's credentials.
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
		authorization_url = await self.ExternalLoginService.initialize_adding_external_account(provider_type, redirect_uri)
		return aiohttp.web.HTTPFound(authorization_url)


	async def login_with_external_account(self, request):
		"""
		Initialize login with external account.
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
		try:
			authorization_url = await self.ExternalLoginService.initialize_signup_with_external_account(
				provider_type, redirect_uri)
		except exceptions.RegistrationNotOpenError:
			L.error("Registration is not open.")
			return self._error_redirect()
		return aiohttp.web.HTTPFound(authorization_url)


	async def external_auth_callback(self, request):
		"""
		Finalize external auth.
		Navigable endpoint, OAuth authorization callback. It must be registered as a redirect URI in OAuth client
		settings at the external account provider.

		---
		parameters:
		-	name: code
			in: query
			description:
				OAuth authorization code.
			schema:
				type: string
		parameters:
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
		elif operation == AuthOperation.AddAccount:
			return await self._add_account_callback(request, authorization_data)
		else:
			raise asab.exceptions.ValidationError("Unknown operation {!r}".format(operation))


	async def _login_callback(self, request, authorization_data):
		access_ips = generic.get_request_access_ips(request)
		try:
			new_sso_session, redirect_uri = await self.ExternalLoginService.finalize_login_with_external_account(
				session_context=request.Session, from_ip=access_ips, **authorization_data)
		except ExternalAccountNotFoundError as e:
			AuditLogger.log(asab.LOG_NOTICE, "Authentication failed", struct_data={
				"ext_provider_type": e.ProviderType,
				"subject_id": e.SubjectId,
				"from_ip": access_ips
			})
			return self._error_redirect()
		except ExternalLoginError as e:
			AuditLogger.log(asab.LOG_NOTICE, "Authentication failed", struct_data={
				"ext_provider_type": e.ProviderType,
				"subject_id": e.SubjectID,
				"from_ip": access_ips
			})
			return self._error_redirect()

		response = aiohttp.web.HTTPFound(redirect_uri)
		self.ExternalLoginService.CookieService.set_session_cookie(
			response,
			cookie_value=new_sso_session.Cookie.Id,
			client_id=new_sso_session.OAuth2.ClientId
		)
		return response


	async def _signup_callback(self, request, authorization_data):
		access_ips = generic.get_request_access_ips(request)
		try:
			new_sso_session, redirect_uri = await self.ExternalLoginService.finalize_signup_with_external_account(
				session_context=request.Session, from_ip=access_ips, **authorization_data)
		except exceptions.RegistrationNotOpenError:
			L.error("Signup with external account denied: Registration is not open.")
			return self._error_redirect()
		except exceptions.CredentialsRegistrationError:
			L.error("Signup with external account failed: Failed to register new credentials.")
			return self._error_redirect()
		except ExternalLoginError:
			return self._error_redirect()

		response = aiohttp.web.HTTPFound(redirect_uri)
		self.ExternalLoginService.CookieService.set_session_cookie(
			response,
			cookie_value=new_sso_session.Cookie.Id,
			client_id=new_sso_session.OAuth2.ClientId
		)
		return response


	async def _add_account_callback(self, request, authorization_data):
		try:
			redirect_uri = await self.ExternalLoginService.finalize_adding_external_account(
				session_context=request.Session, **authorization_data)
		except ExternalAccountAlreadyUsedError as e:
			L.log(asab.LOG_NOTICE, "Adding external account denied: Account already used.", struct_data={
				"cid": e.CredentialsId, "type": e.ProviderType, "sub": e.SubjectID})
			return self._error_redirect()
		except ExternalLoginError:
			return self._error_redirect()

		response = aiohttp.web.HTTPFound(redirect_uri)
		return response


	def _error_redirect(self):
		"""
		Error redirection when the original authorization flow cannot be resumed
		"""
		response = aiohttp.web.HTTPNotFound(headers={
			"Location": self.ExternalLoginService.ErrorRedirectUrl,
			"Refresh": "0;url=" + self.ExternalLoginService.ErrorRedirectUrl,
		})
		return response


	def _redirect_to_account_settings(self):
		"""
		Redirect to Seacat Account webui
		"""
		response = aiohttp.web.HTTPFound(self.ExternalLoginService.MyAccountPageUrl)
		return response
