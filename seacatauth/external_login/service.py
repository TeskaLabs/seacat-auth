import logging
import secrets
import aiohttp
import typing

import asab
import asab.web.rest

from .. import exceptions, AuditLogger
from ..last_activity import EventCode
from .utils import AuthOperation
from .providers import create_provider, GenericOAuth2Login
from .storage import ExternalLoginStateStorage, ExternalLoginAccountStorage


#

L = logging.getLogger(__name__)

#


asab.Config.add_defaults({
	"seacatauth:external_login": {
		# URI for the external registration of unknown accounts from external identity providers.
		"registration_webhook_uri": "",
		"state_expiration": "10m",
		"state_length": 16,
		"nonce_length": 16,
		"error_redirect_url": ""
	}})


class ExternalLoginService(asab.Service):

	ExternalLoginAccountCollection = "el"
	ExternalLoginStateCollection = "els"

	def __init__(self, app, service_name="seacatauth.ExternalLoginService"):
		super().__init__(app, service_name)
		self.SessionService = None
		self.AuthenticationService = None
		self.CredentialsService = None
		self.RegistrationService = None
		self.TenantService = None
		self.RoleService = None
		self.LastActivityService = None
		self.CookieService = None

		self.ExternalLoginStateStorage = ExternalLoginStateStorage(self.App)
		self.ExternalLoginAccountStorage = ExternalLoginAccountStorage(self.App)

		self.StateLength = asab.Config.getint("seacatauth:external_login", "state_length")
		self.NonceLength = asab.Config.getint("seacatauth:external_login", "nonce_length")
		self.RegistrationWebhookUri = asab.Config.get(
			"seacatauth:external_login", "registration_webhook_uri").rstrip("/")

		self.CallbackEndpointPath = "/public/ext-login/callback"
		self.CallbackUrlTemplate = "{}{}".format(
			app.PublicSeacatAuthApiUrl,
			self.CallbackEndpointPath.lstrip("/")
		)
		self.MyAccountPageUrl = "{}#/".format(app.AuthWebUiUrl)
		self.ErrorRedirectUrl = asab.Config.get("seacatauth:external_login", "error_redirect_url")
		if not self.ErrorRedirectUrl:
			self.ErrorRedirectUrl = self.MyAccountPageUrl

		self.Providers: typing.Dict[str, GenericOAuth2Login] = self._prepare_providers()


	async def initialize(self, app):
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.RegistrationService = app.get_service("seacatauth.RegistrationService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.LastActivityService = app.get_service("seacatauth.LastActivityService")
		self.CookieService = app.get_service("seacatauth.CookieService")

		for provider in self.Providers.values():
			await provider.initialize(app)

		await self.ExternalLoginAccountStorage.initialize()


	def _prepare_providers(self):
		providers = {}
		for section in asab.Config.sections():
			provider = create_provider(self, section)
			if provider is not None:
				providers[provider.Type] = provider
		return providers


	def get_provider(self, provider_type: str) -> GenericOAuth2Login:
		try:
			return self.Providers[provider_type]
		except KeyError:
			raise exceptions.ProviderNotFoundError(provider_id=provider_type)


	async def initialize_login_with_external_account(
		self,
		provider_type: str,
		redirect_uri: typing.Optional[str]
	) -> str:
		return await self._initialize_external_auth(
			provider_type, operation=AuthOperation.LogIn, redirect_uri=redirect_uri)


	async def initialize_signup_with_external_account(
		self,
		provider_type: str,
		redirect_uri: typing.Optional[str]
	) -> str:
		if not self._can_register_new_credentials():
			raise NotImplementedError("Sign up with external account: Sign up is not allowed")
		return await self._initialize_external_auth(
			provider_type, operation=AuthOperation.SignUp, redirect_uri=redirect_uri)


	async def initialize_adding_external_account(
		self,
		provider_type: str,
		redirect_uri: typing.Optional[str]
	) -> str:
		return await self._initialize_external_auth(
			provider_type, operation=AuthOperation.AddAccount, redirect_uri=redirect_uri)


	async def _initialize_external_auth(
		self,
		provider_type: str,
		operation: AuthOperation,
		redirect_uri: typing.Optional[str],
	) -> str:
		provider = self.Providers[provider_type]
		state_id = operation.value + secrets.token_urlsafe(self.StateLength - 1)
		nonce = secrets.token_urlsafe(self.NonceLength)
		state_id = await self.ExternalLoginStateStorage.create(state_id, provider_type, operation, redirect_uri, nonce)
		return provider.get_authorize_uri(state=state_id, nonce=nonce)


	async def _get_user_info(self, provider_type: str, authorization_data: dict, expected_nonce: str):
		"""
		Obtain user info from external account provider and verify that it contains the mandatory claims.
		"""
		provider = self.Providers[provider_type]
		user_info = await provider.get_user_info(authorization_data, expected_nonce)
		if user_info is None:
			L.error("Cannot obtain user info from external login provider.")
			raise exceptions.ExternalLoginError("Failed to obtain user info", provider=provider_type)
		if "sub" not in user_info:
			L.error("User info does not contain the 'sub' (subject ID) claim.")
			raise exceptions.ExternalLoginError(
				"User info does not contain the 'sub' (subject ID) claim.", provider=provider_type)
		return user_info


	async def finalize_login_with_external_account(
		self,
		session_context,
		state: str,
		from_ip: typing.Optional[list] = None,
		**authorization_data: dict
	) -> typing.Tuple[typing.Any, str]:
		"""
		Log the user in using their external account.

		@param session_context: Request session (or None)
		@param state: State parameter from the authorization response query
		@param authorization_data: Authorization response query
		@return: New SSO session object and redirect URI
		"""
		state = await self.ExternalLoginStateStorage.get(state)
		assert state["operation"] == AuthOperation.LogIn

		# Finish the authorization flow by obtaining user info from the external login provider
		provider_type = state["provider"]
		user_info = await self._get_user_info(provider_type, authorization_data, expected_nonce=state.get("nonce"))

		# Find the external account and its associated Seacat credentials ID
		try:
			account = await self.get_external_account(provider_type, subject=user_info["sub"])
			credentials_id = account["cid"]
		except exceptions.ExternalAccountNotFoundError:
			# Unknown external account
			if session_context and not session_context.is_anonymous():
				# Some user is already logged in
				# TODO: Offer the user to add the new external account
				raise NotImplementedError("Login with external account: Unknown external account with a valid SSO session")
			else:
				# TODO: Offer the user to sign up
				raise NotImplementedError("Login with external account: Unknown external account")

		# Log the user in
		if session_context:
			# Some user is already logged in
			if session_context.Credentials.Id == credentials_id:
				# The external account belongs to the user that is already logged in
				# Re-log in
				sso_session = await self._login(
					credentials_id=credentials_id,
					provider_type=provider_type,
					current_sso_session=session_context,
					from_ip=from_ip,
				)
			else:
				# The external account belongs to someone else than who is logged in
				# Ignore the current SSO session and log in, its cookie will be overwritten
				sso_session = await self._login(
					credentials_id=credentials_id,
					provider_type=provider_type,
					from_ip=from_ip,
				)
		else:
			sso_session = await self._login(
				credentials_id=credentials_id,
				provider_type=provider_type,
				from_ip=from_ip,
			)

		await self.ExternalLoginStateStorage.delete(state["_id"])

		redirect_uri = self._get_final_redirect_uri(state)

		return sso_session, redirect_uri


	async def finalize_signup_with_external_account(
		self,
		session_context,
		state: str,
		**authorization_data: dict
	) -> typing.Tuple[typing.Any, str]:
		"""
		Sign up a new user using their external account.

		@param session_context: Request session (or None)
		@param state: State parameter from the authorization response query
		@param authorization_data: Authorization response query
		@return: New SSO session object and redirect URI
		"""
		if not self._can_register_new_credentials():
			raise NotImplementedError("Sign up with external account: Sign up is not allowed")

		if session_context and not session_context.is_anonymous():
			raise NotImplementedError("Sign up with external account: Someone is logged in already")

		state = await self.ExternalLoginStateStorage.get(state)
		assert state["operation"] == AuthOperation.SignUp

		# Finish the authorization flow by obtaining user info from the external login provider
		provider_type = state["provider"]
		user_info = await self._get_user_info(provider_type, authorization_data, expected_nonce=state.get("nonce"))

		# Verify that the external account is not registered already
		try:
			await self.get_external_account(provider_type, subject=user_info["sub"])
			# Account already registered
			# TODO: Offer the user to log in instead
			raise NotImplementedError("Sign up with external account: External account already registered")
		except exceptions.ExternalAccountNotFoundError:
			# Unknown account can be used for signup
			pass

		# Create Seacat credentials
		credentials_id = await self._create_new_seacat_auth_credentials(provider_type, user_info)
		# Add the external account to the just created credentials
		await self.ExternalLoginAccountStorage.create(credentials_id, provider_type, user_info)

		# Log the user in
		raise NotImplementedError("Sign up with external account: Auto login after sign up")

		await self.ExternalLoginStateStorage.delete(state["_id"])

		redirect_uri = self._get_final_redirect_uri(state)

		return sso_session, redirect_uri


	async def finalize_adding_external_account(
		self,
		session_context,
		state: str,
		**authorization_data: dict
	) -> str:
		"""
		Add a new external account to the current user's credentials

		@param session_context: Request session
		@param state: State parameter from the authorization response query
		@param authorization_data: Authorization response query
		@return: Redirect URI
		"""
		if not session_context or session_context.is_anonymous():
			raise exceptions.AccessDeniedError("Authentication required")
		credentials_id = session_context.Credentials.Id

		state = await self.ExternalLoginStateStorage.get(state)
		assert state["operation"] == AuthOperation.AddAccount

		# Finish the authorization flow by obtaining user info from the external login provider
		provider_type = state["provider"]
		user_info = await self._get_user_info(provider_type, authorization_data, expected_nonce=state.get("nonce"))

		# TODO: Require fresh authentication and user confirmation
		try:
			await self.ExternalLoginAccountStorage.create(credentials_id, provider_type, user_info)
		except asab.exceptions.Conflict as e:
			raise NotImplementedError("Add external account: External account already registered") from e

		await self.ExternalLoginStateStorage.delete(state["_id"])

		redirect_uri = self._get_final_redirect_uri(state)

		return redirect_uri


	async def list_external_accounts(self, credentials_id: str):
		return await self.ExternalLoginAccountStorage.list(credentials_id)


	async def get_external_account(
		self,
		provider_type: str,
		subject: str,
		credentials_id: typing.Optional[str] = None
	) -> dict:
		try:
			account = await self.ExternalLoginAccountStorage.get(provider_type, subject)
		except KeyError:
			raise exceptions.ExternalAccountNotFoundError(provider_type, subject)
		if credentials_id and credentials_id != account["cid"]:
			raise exceptions.ExternalAccountNotFoundError(provider_type, subject)
		return account


	async def update_external_account(
		self,
		provider_type: str,
		subject: str,
		credentials_id: typing.Optional[str] = None,
		**kwargs
	):
		account = await self.get_external_account(provider_type, subject, credentials_id)
		if credentials_id and credentials_id != account["cid"]:
			raise exceptions.ExternalAccountNotFoundError(provider_type, subject)
		return await self.ExternalLoginAccountStorage.update(provider_type, subject, **kwargs)


	async def remove_external_account(
		self,
		provider_type: str,
		subject: str,
		credentials_id: typing.Optional[str] = None
	):
		account = await self.get_external_account(provider_type, subject, credentials_id)
		if credentials_id and credentials_id != account["cid"]:
			raise exceptions.ExternalAccountNotFoundError(provider_type, subject)
		return await self.ExternalLoginAccountStorage.delete(provider_type, subject)


	async def _login(
		self,
		credentials_id: str,
		provider_type: str,
		current_sso_session = None,
		from_ip: typing.Optional[typing.Iterable] = None
	):
		# Create ad-hoc login descriptor
		login_descriptor = {
			"id": "!external",
			"factors": [{"type": "ext:{}".format(provider_type)}]
		}

		session_builders = await self.SessionService.build_sso_root_session(
			credentials_id=credentials_id,
			login_descriptor=login_descriptor,
		)
		if current_sso_session and not current_sso_session.is_anonymous():
			# Update existing SSO root session (re-login)
			assert current_sso_session.Session.Type == "root"
			assert current_sso_session.Credentials.Id == credentials_id
			new_sso_session = await self.SessionService.update_session(
				current_sso_session.SessionId,
				session_builders=session_builders
			)
		else:
			# Create a new root session
			new_sso_session = await self.SessionService.create_session(
				session_type="root",
				session_builders=session_builders,
			)

		AuditLogger.log(asab.LOG_NOTICE, "Authentication successful", struct_data={
			"cid": credentials_id,
			"lsid": "<external-login>",
			"sid": str(new_sso_session.Session.Id),
			"from_ip": from_ip,
			"authn_by": login_descriptor,
		})
		await self.LastActivityService.update_last_activity(
			EventCode.LOGIN_SUCCESS, credentials_id, from_ip=from_ip, authn_by=login_descriptor)

		return new_sso_session


	def _can_register_new_credentials(self):
		return self.RegistrationWebhookUri is not None or self.RegistrationService.SelfRegistrationEnabled


	async def _create_new_seacat_auth_credentials(
		self,
		provider_type: str,
		user_info: dict,
	) -> str:
		"""
		Attempt to create new Seacat Auth credentials for external user.
		"""
		if self.RegistrationWebhookUri:
			# Register external user via webhook
			credentials_id = await self._create_credentials_via_webhook(provider_type, user_info)
		else:
			assert self.RegistrationService.SelfRegistrationEnabled
			# Attempt registration with local credential providers if registration is enabled
			cred_data = {
				"username": user_info.get("preferred_username"),
				"email": user_info.get("email"),
				"phone": user_info.get("phone_number"),
			}
			try:
				credentials_id = await self.RegistrationService.CredentialProvider.create(cred_data)
			except Exception as e:
				raise exceptions.CredentialsRegistrationError(
					"Failed to register credentials: {}".format(e), credentials=cred_data)

		assert credentials_id
		return credentials_id


	async def _create_credentials_via_webhook(
		self,
		provider_type: str,
		user_info: dict,
	) -> str:
		"""
		Send external login user_info to webhook for registration.
		If the server responds with 200 and the JSON body contains 'cid' of the registered credentials,
		create an entry in the external login collection and return the credential ID.
		Otherwise, return None.
		"""
		assert self.RegistrationWebhookUri is not None

		request_data = {
			"provider_type": provider_type,
			"user_info": user_info,
		}

		async with aiohttp.ClientSession() as session:
			async with session.post(self.RegistrationWebhookUri, json=request_data) as resp:
				if resp.status not in frozenset([200, 201]):
					text = await resp.text()
					L.error("Webhook responded with error", struct_data={
						"status": resp.status, "text": text, "url": self.RegistrationWebhookUri})
					raise exceptions.CredentialsRegistrationError("Webhook responded with error")
				response_data = await resp.json()

		credentials_id = response_data.get("credential_id")
		if not credentials_id:
			L.error("Webhook response does not contain valid 'credential_id'", struct_data={
				"response_data": response_data})
			raise exceptions.CredentialsRegistrationError("Unexpected webhook response")

		# Test if the ID is reachable
		try:
			await self.CredentialsService.get(credentials_id)
		except KeyError:
			L.error("Returned credential ID not found", struct_data={"response_data": response_data})
			raise exceptions.CredentialsRegistrationError("Returned credential ID not found")

		return credentials_id


	def _get_final_redirect_uri(self, state: dict):
		if "redirect_uri" in state and state["redirect_uri"]:
			return state["redirect_uri"]
		# No redirect_uri was specified; redirect to default URL
		return self.MyAccountPageUrl
