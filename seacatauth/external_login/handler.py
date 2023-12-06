import logging
import urllib.parse

import aiohttp.web
import asab
import asab.web.rest

from .service import ExternalLoginService
from .. import generic
from ..decorators import access_control
from ..cookie.utils import set_cookie, delete_cookie

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
		web_app.router.add_get(self.ExternalLoginService.CallbackEndpointPath, self.login_callback)
		web_app.router.add_delete("/public/ext-login/{ext_login_provider}", self.unregister_external_login)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get(self.ExternalLoginService.CallbackEndpointPath, self.login_callback)
		web_app_public.router.add_delete("/public/ext-login/{ext_login_provider}", self.unregister_external_login)


	async def login_callback(self, request):
		"""
		Log in with a registered external provider account
		"""
		cookie_svc = self.App.get_service("seacatauth.CookieService")
		client_svc = self.App.get_service("seacatauth.ClientService")

		if request.method == "POST":
			authorize_data: dict = dict(await request.post())
		else:
			authorize_data = dict(request.query)
		if not authorize_data:
			L.error("External login provider returned no data in authorize callback")

		state_id = authorize_data.get("state")
		try:
			state = await self.ExternalLoginService.pop_authorization_state(state_id)
		except KeyError:
			L.log(asab.LOG_NOTICE, "External login authorization state not found", struct_data={
				"state_id": state_id})
			# TODO: Where to redirect in case of failure?
			return
		login_provider_type = state["type"]

		provider = self.ExternalLoginService.get_provider(login_provider_type)
		user_info = await provider.get_user_info(authorize_data, expected_nonce=state.get("nonce"))

		if user_info is None:
			L.error("Cannot obtain user info from external login provider")
			response = self._login_redirect_response(state=state, error="external_login_failed")
			delete_cookie(self.App, response)
			return response

		sub = user_info.get("sub")
		if sub is None:
			L.error("Cannot obtain sub id from external login provider")
			response = self._login_redirect_response(state=state, error="external_login_failed")
			delete_cookie(self.App, response)
			return response
		sub = str(sub)

		# Get credentials by sub
		credentials_id = None
		try:
			el_credentials = await self.ExternalLoginService.get(login_provider_type, sub)
			credentials_id = el_credentials["cid"]
		except KeyError:
			# Credentials do not exist in Seacat Auth
			L.info("Unknown external login credential.", struct_data={"provider_type": provider.Type, "sub": sub})
			# TODO: Attempt registration with local credential providers if enabled.
			# Attempt registration via webhook
			if self.ExternalLoginService.RegistrationWebhookUri:
				# Do not send the authorization code
				authorize_data_safe = {k: v for k, v in authorize_data.items() if k != "code"}
				credentials_id = await self.ExternalLoginService.register_credentials_via_webhook(
					login_provider_type, authorize_data_safe, user_info)
		if credentials_id is None:
			response = self._login_redirect_response(state=state, error="external_login_failed")
			delete_cookie(self.App, response)
			return response

		# Create a placeholder login session
		# TODO: Save the external login provider as a login factor
		login_descriptors = []
		login_session = await self.AuthenticationService.create_login_session(
			credentials_id=credentials_id,
			client_public_key=None,
			login_descriptors=login_descriptors,
			ident=None
		)

		# Create ad-hoc login descriptor
		login_factor = "!ext-{}".format(login_provider_type)
		login_session.AuthenticatedVia = {
			"id": "!external",
			"label": "Login via {}".format(login_provider_type),
			"factors": [
				{"id": login_factor, "type": login_factor}
			]
		}

		# Get the IP addresses where the login request came from
		access_ips = [request.remote]
		ff = request.headers.get("X-Forwarded-For")
		if ff is not None:
			access_ips.extend(ff.split(", "))

		# Finish login and create session
		session = await self.AuthenticationService.login(login_session, from_info=access_ips)
		if session is None:
			L.error("Failed to create session")
			response = self._login_redirect_response(state=state, error="external_login_failed")
			delete_cookie(self.App, response)
			return response

		L.log(asab.LOG_NOTICE, "External login successful", struct_data={
			"cid": credentials_id,
			"login_type": provider.Type
		})
		response = self._my_account_redirect_response(state=state)

		# Get cookie domain
		cookie_domain = cookie_svc.RootCookieDomain
		if hasattr(login_session, "ClientId"):
			try:
				client = await client_svc.get(login_session.ClientId)
				cookie_domain = client.get("cookie_domain")
			except KeyError:
				L.error("Client not found.", struct_data={"client_id": login_session.ClientId})

		set_cookie(self.App, response, session, cookie_domain)

		return response


	@access_control()
	async def unregister_external_login(self, request, *, credentials_id):
		"""
		Unregister an external login provider account
		"""
		provider_type = request.match_info["ext_login_provider"]
		el_credentials = await self.ExternalLoginService.get_sub(credentials_id, provider_type)
		await self.ExternalLoginService.delete(provider_type, sub=el_credentials["s"])

		L.log(asab.LOG_NOTICE, "External login successfully removed", struct_data={
			"cid": credentials_id,
			"type": provider_type,
		})

		response = {"result": "OK"}
		return asab.web.rest.json_response(request, response)


	async def _redirect_to_authorization(self, oauth_query: dict):
		oidc_service = self.App.get_service("seacatauth.OpenIdConnectService")
		authorization_uri = "{}?{}".format(
			oidc_service.authorization_endpoint_url(),
			urllib.parse.urlencode(oauth_query))
		return aiohttp.web.HTTPFound(location=authorization_uri)
