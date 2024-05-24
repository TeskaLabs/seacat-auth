import logging

import aiohttp.web
import asab
import asab.web.rest

from seacatauth.external_login.service import ExternalLoginService
from seacatauth import exceptions
from seacatauth.external_login.utils import AuthOperation

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

		web_app.router.add_get("/public/ext-login/{provider_type}/login", self.login_with_external_account)
		web_app.router.add_get("/public/ext-login/{provider_type}/signup", self.sign_up_with_external_account)
		web_app.router.add_get(self.ExternalLoginService.CallbackEndpointPath, self.external_auth_callback)

		web_app_public.router.add_get("/public/ext-login/{provider_type}/login", self.login_with_external_account)
		web_app_public.router.add_get("/public/ext-login/{provider_type}/signup", self.sign_up_with_external_account)
		web_app_public.router.add_get(self.ExternalLoginService.CallbackEndpointPath, self.external_auth_callback)


	async def login_with_external_account(self, request):
		"""
		Initialize login with external account.
		Navigable endpoint, redirects to external login page.
		"""
		redirect_uri = request.query.get("redirect_uri")
		provider_type = request.match_info["provider_type"]
		authorization_url = await self.ExternalLoginService.login_with_external_account_initialize(
			provider_type, redirect_uri)
		return aiohttp.web.HTTPFound(location=authorization_url)


	async def sign_up_with_external_account(self, request):
		"""
		Initialize sign up with external account.
		Navigable endpoint, redirects to external login page.
		"""
		redirect_uri = request.query.get("redirect_uri")
		provider_type = request.match_info["provider_type"]
		authorization_url = await self.ExternalLoginService.sign_up_with_external_account_initialize(
			provider_type, redirect_uri)
		return aiohttp.web.HTTPFound(location=authorization_url)


	async def external_auth_callback(self, request):
		"""
		Finalize external auth.
		Navigable endpoint, OAuth authorization callback. It must be registered as a redirect URI in OAuth client
		settings at the external account provider.
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
		try:
			new_sso_session, redirect_uri = await self.ExternalLoginService.finalize_login_with_external_account(
				session_context=request.Session, **authorization_data)
		except exceptions.ExternalLoginError:
			return self._error_redirect()

		response = aiohttp.web.HTTPFound(location=redirect_uri)
		self.ExternalLoginService.CookieService.set_session_cookie(
			response,
			cookie_value=new_sso_session.Cookie.Id,
			client_id=new_sso_session.OAuth2.ClientId
		)
		return response


	async def _signup_callback(self, request, authorization_data):
		try:
			new_sso_session, redirect_uri = await self.ExternalLoginService.finalize_signup_with_external_account(
				session_context=request.Session, **authorization_data)
		except exceptions.ExternalLoginError:
			return self._error_redirect()

		response = aiohttp.web.HTTPFound(location=redirect_uri)
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
		except exceptions.ExternalLoginError:
			return self._error_redirect()

		response = aiohttp.web.HTTPFound(location=redirect_uri)
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
		response = aiohttp.web.HTTPFound(location=self.ExternalLoginService.MyAccountPageUrl)
		return response
