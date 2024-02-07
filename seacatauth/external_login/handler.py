import logging
import urllib.parse

import aiohttp.web
import asab
import asab.web.rest

from .service import ExternalLoginService
from .. import generic, exceptions
from ..decorators import access_control
from ..cookie.utils import set_cookie

#

L = logging.getLogger(__name__)

#


class ExternalLoginHandler(object):
	"""
	External login

	---
	tags: ["External login"]
	"""

	def __init__(self, app, external_login_svc: ExternalLoginService):
		self.App = app
		self.ExternalLoginService = external_login_svc
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_get(
			self.ExternalLoginService.CallbackEndpointPath, self.login_callback)
		web_app.router.add_delete(
			"/account/ext-login/{provider_type}", self.remove_external_login_credential)
		web_app.router.add_delete(
			"/account/ext-login/{provider_type}/{sub}", self.remove_external_login_credential)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get(
			"/public/ext-login/{provider_type}/initialize", self.initialize_login)
		web_app_public.router.add_get(
			self.ExternalLoginService.CallbackEndpointPath, self.login_callback)


	async def initialize_login(self, request):
		login_session_id = request.query.get("lsid")
		provider_type = request.match_info["provider_type"]
		try:
			provider = self.ExternalLoginService.get_provider(provider_type)
		except KeyError:
			# Authorization flow broken
			L.error("Unsupported external login provider type", struct_data={
				"provider_type": provider_type})
			return self._error_redirect()

		authorization_url = await self.ExternalLoginService.prepare_external_login_url(
			provider, login_session_id, request.Session)
		return aiohttp.web.HTTPFound(location=authorization_url)


	async def login_callback(self, request):
		"""
		Process external login provider authorization response, negotiate ID token / user info, and
		- if the user is not logged in and the external credential is known, log the user in;
		- if the user is not logged in and the external credential is not known, attempt registration;
		- if the user is logged in, assign the external credential to them.
		Finally, redirect the user agent to the authorization endpoint and resume the authorization flow.
		"""
		provider_type = request.match_info["provider_type"]
		try:
			provider = self.ExternalLoginService.get_provider(provider_type)
		except KeyError:
			# Authorization flow broken
			L.error("Unsupported external login provider type", struct_data={
				"provider_type": provider_type})
			return self._error_redirect()

		if request.method == "POST":
			authorization_data: dict = dict(await request.post())
		else:
			authorization_data = dict(request.query)
		if not authorization_data:
			# Authorization flow broken
			L.error("External login provider returned no data in authorize callback")
			return self._error_redirect()

		login_session_id = authorization_data.get("state")
		try:
			login_session = await self.AuthenticationService.get_login_session(login_session_id)
		except KeyError:
			# Authorization flow broken
			L.error("Login session not found", struct_data={
				"lsid": login_session_id})
			return self._error_redirect()

		try:
			provider_data = login_session.ExternalLogin[provider_type]
		except AttributeError:
			L.error("External login not initialized", struct_data={
				"lsid": login_session_id})
			return self._error_redirect()
		except KeyError:
			L.error("External login not initialized", struct_data={
				"lsid": login_session_id, "provider": provider_type})
			return self._error_redirect()

		user_info = await provider.get_user_info(authorization_data, expected_nonce=provider_data.get("nonce"))
		if user_info is None:
			# Authorization flow broken
			L.error("Cannot obtain user info from external login provider")
			return self._error_redirect()

		subject = user_info.get("sub")
		if subject is None:
			# Authorization flow broken
			L.error("User info does not contain 'sub' (subject ID)")
			return self._error_redirect()
		subject = str(subject)  # Sometimes sub is an integer

		# Try to find Seacat Auth credentials associated with the subject ID
		try:
			external_credentials = await self.ExternalLoginService.get(provider_type, subject)
			external_cid = external_credentials.get("cid")
		except KeyError:
			external_cid = None
		subject_known = external_cid is not None

		# Check if the request is authenticated (user is already signed in)
		authenticated_cid = None
		print("request.Sess", request.Session)
		if request.Session and not request.Session.is_anonymous():
			# Verify that the current session is the same as the one that initiated the external login
			assert request.Session.Id == login_session.InitiatorSessionId
			assert request.Session.Credentials.Id == login_session.InitiatorCredentialsId
			print(request.Session.Id, login_session.InitiatorSessionId)
			print(request.Session.Credentials.Id, login_session.InitiatorCredentialsId)
			authenticated_cid = login_session.InitiatorCredentialsId
		signed_in = authenticated_cid is not None

		from_ip = generic.get_request_access_ips(request)

		new_session = None
		print(f"{subject_known=} {signed_in=} {external_cid=}")
		if subject_known:
			# (Re)authentication successful - Create a new root session or update the existing one
			new_session = await self.ExternalLoginService.login(
				login_session, provider_type, subject, from_ip=from_ip)

		elif signed_in:
			# Assign subject ID to the current Seacat Auth credentials and update current root session
			# TODO: Redirect the user to a page where they can confirm the action.
			#   e.g. "Hey user ABC, do you want to use Google account "XYZ" to log in?"
			await self.ExternalLoginService.create(authenticated_cid, provider_type, user_info)
			new_session = await self.ExternalLoginService.login(
				login_session, provider_type, subject, from_ip=from_ip)

		elif self.ExternalLoginService.can_register_new_credentials():
			# Register new Seacat Auth credentials, either directly or via webhook
			# Do not send the authorization code
			authorize_data_safe = {k: v for k, v in authorization_data.items() if k != "code"}
			try:
				credentials_id = await self.ExternalLoginService.create_new_seacat_auth_credentials(
					provider_type, user_info, authorize_data_safe)
				new_session = await self.ExternalLoginService.login(
					login_session, provider_type, subject, from_ip=from_ip)
			except exceptions.CredentialsRegistrationError:
				L.error("Failed to register credential from external login", struct_data={
					"provider": provider.Type, "sub": subject})

		else:
			# TODO: Unknown user, cannot register
			...

		if new_session is None:
			# External login failed or was denied
			if login_session.AuthorizationParams:
				# Resume the authorization flow WITHOUT the acr_values parameter
				# This will send the user agent to the Seacat Auth login page
				oauth_query = {
					k: v
					for k, v in login_session.AuthorizationParams.items()
					if k not in {"acr_values", "prompt"}
				}
				return self._redirect_to_authorization(oauth_query)
			else:
				# The auth flow did not start at the authorization endpoint
				return self._redirect_to_account_settings()

		if login_session.AuthorizationParams:
			oauth_query = {
				k: v
				for k, v in login_session.AuthorizationParams.items()
				if k not in {"prompt"}
			}
			response = self._redirect_to_authorization(oauth_query)
		else:
			response = self._redirect_to_account_settings()

		set_cookie(self.App, response, new_session)

		return response


	@access_control()
	async def remove_external_login_credential(self, request, *, credentials_id):
		"""
		Unregister an external login credential
		"""
		provider_type = request.match_info["provider_type"]
		sub = request.match_info.get("sub")
		if not sub:
			el_credentials = await self.ExternalLoginService.get_by_cid(credentials_id, provider_type)
			sub = el_credentials["s"]
		await self.ExternalLoginService.delete(provider_type, sub=sub)

		L.log(asab.LOG_NOTICE, "External login successfully removed", struct_data={
			"cid": credentials_id,
			"type": provider_type,
		})

		response = {"result": "OK"}
		return asab.web.rest.json_response(request, response)


	def _redirect_to_authorization(self, oauth_query: dict):
		"""
		Resume the original authorization flow
		"""
		oidc_service = self.App.get_service("seacatauth.OpenIdConnectService")
		authorization_uri = "{}?{}".format(
			oidc_service.authorization_endpoint_url(),
			urllib.parse.urlencode(oauth_query))
		response = aiohttp.web.HTTPFound(location=authorization_uri)
		return response


	def _error_redirect(self):
		"""
		Error redirection when the original authorization flow cannot be resumed
		"""
		response = aiohttp.web.HTTPNotFound(headers={
			"Location": self.ExternalLoginService.MyAccountPageUrl,
			"Refresh": "0;url=" + self.ExternalLoginService.MyAccountPageUrl,
		})
		return response


	def _redirect_to_account_settings(self):
		"""
		Redirect to Seacat Account webui
		"""
		response = aiohttp.web.HTTPFound(location=self.ExternalLoginService.MyAccountPageUrl)
		return response
