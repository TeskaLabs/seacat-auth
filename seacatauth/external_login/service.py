import datetime
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

	ExternalLoginAccountCollection = "ela"
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


	async def login_with_external_account_initialize(self, provider_type: str, redirect_uri: str) -> str:
		return await self._initialize_external_auth(
			provider_type, action=AuthOperation.LogIn, redirect_uri=redirect_uri)


	async def sign_up_with_external_account_initialize(self, provider_type: str, redirect_uri: str) -> str:
		return await self._initialize_external_auth(
			provider_type, action=AuthOperation.SignUp, redirect_uri=redirect_uri)


	async def add_external_account_initialize(self, provider_type: str, redirect_uri: str) -> str:
		return await self._initialize_external_auth(
			provider_type, action=AuthOperation.AddAccount, redirect_uri=redirect_uri)


	async def _initialize_external_auth(self, provider_type: str, action: AuthOperation, redirect_uri: str) -> str:
		provider = self.get_provider(provider_type)
		state_id = secrets.token_urlsafe(16)
		nonce = secrets.token_urlsafe(16)
		state_id = await self.ExternalLoginStateStorage.create(state_id, provider_type, action, redirect_uri, nonce)
		return provider.get_authorize_uri(state=state_id, nonce=nonce)


	async def finalize_external_auth(self, state: str, **authorization_data: dict):
		state = await self.ExternalLoginStateStorage.get(state)
		state["action"]
		state["type"]


	async def add_account(self, credentials_id: str, provider_type: str, user_info: dict | None = None):
		await self.ExternalLoginAccountStorage.create(credentials_id, provider_type, user_info)


	async def list_accounts(self, credentials_id: str):
		return await self.ExternalLoginAccountStorage.list(credentials_id)


	async def get_account(self, provider_type: str, sub: str, credentials_id: typing.Optional[str] = None) -> dict:
		try:
			account = await self.ExternalLoginAccountStorage.get(provider_type, sub)
		except KeyError:
			raise exceptions.ExternalAccountNotFoundError(provider_type, sub)
		if credentials_id and credentials_id != account["cid"]:
			raise exceptions.ExternalAccountNotFoundError(provider_type, sub)
		return account


	async def update_account(self, provider_type: str, sub: str, credentials_id: typing.Optional[str] = None, **kwargs):
		account = await self.get_account(provider_type, sub, credentials_id)
		if credentials_id and credentials_id != account["cid"]:
			raise exceptions.ExternalAccountNotFoundError(provider_type, sub)
		return await self.ExternalLoginAccountStorage.update(provider_type, sub, **kwargs)


	async def remove_account(self, provider_type: str, sub: str, credentials_id: typing.Optional[str] = None):
		account = await self.get_account(provider_type, sub, credentials_id)
		if credentials_id and credentials_id != account["cid"]:
			raise exceptions.ExternalAccountNotFoundError(provider_type, sub)
		return await self.ExternalLoginAccountStorage.delete(provider_type, sub)


	def can_register_new_credentials(self):
		return self.RegistrationWebhookUri is not None or self.RegistrationService.SelfRegistrationEnabled


	async def create_new_seacat_auth_credentials(
		self,
		provider_type: str,
		user_info: dict,
		authorization_data: dict,
	) -> str | None:
		"""
		Attempt to create new Seacat Auth credentials for external user.
		"""
		if self.RegistrationWebhookUri:
			# Register external user via webhook
			credentials_id = await self.register_credentials_via_webhook(
				provider_type, authorization_data, user_info)
		elif self.RegistrationService.SelfRegistrationEnabled:
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
		else:
			raise exceptions.CredentialsRegistrationError("New credential registration via external login is disabled")

		await self.create(
			credentials_id=credentials_id,
			provider_type=provider_type,
			user_info=user_info)
		return credentials_id


	async def register_credentials_via_webhook(
		self,
		provider_type: str,
		authorize_data: dict,
		user_info: dict,
	) -> str | None:
		"""
		Send external login user_info to webhook for registration.
		If the server responds with 200 and the JSON body contains 'cid' of the registered credentials,
		create an entry in the external login collection and return the credential ID.
		Otherwise, return None.
		"""
		assert self.RegistrationWebhookUri is not None

		request_data = {
			"provider_type": provider_type,
			"authorization_response": authorize_data,
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


	async def login(
		self,
		login_session,
		provider_type: str,
		subject: str,
		from_ip: typing.Iterable | None = None
	) -> dict:
		ext_credentials = await self.get(provider_type, subject)
		credentials_id = ext_credentials["cid"]

		# Create ad-hoc login descriptor
		login_descriptor = {
			"id": "!external",
			"factors": [{"type": "ext:{}".format(provider_type)}]
		}

		if login_session.InitiatorSessionId:
			try:
				root_session = await self.SessionService.get(login_session.InitiatorSessionId)
			except exceptions.SessionNotFoundError as e:
				L.log(
					asab.LOG_NOTICE,
					"The session that initiated the login session no longer exists",
					struct_data={"sid": login_session.InitiatorSessionId, "lsid": login_session.Id}
				)
				root_session = None
		else:
			root_session = None

		scope = frozenset(["profile", "email", "phone"])

		ext_login_svc = self.App.get_service("seacatauth.ExternalLoginService")
		session_builders = [
			await credentials_session_builder(self.CredentialsService, credentials_id, scope),
			await authz_session_builder(
				tenant_service=self.TenantService,
				role_service=self.RoleService,
				credentials_id=credentials_id,
				tenants=None  # Root session is tenant-agnostic
			),
			authentication_session_builder(login_descriptor),
			await available_factors_session_builder(self.AuthenticationService, credentials_id),
			await external_login_session_builder(ext_login_svc, credentials_id),
		]

		if root_session and not root_session.is_anonymous():
			# Update existing root session
			new_session = await self.SessionService.update_session(
				root_session.SessionId,
				session_builders=session_builders
			)
		else:
			# Create a new root session
			session_builders.append(cookie_session_builder())
			new_session = await self.SessionService.create_session(
				session_type="root",
				session_builders=session_builders,
			)

		AuditLogger.log(asab.LOG_NOTICE, "Authentication successful", struct_data={
			"cid": credentials_id,
			"lsid": login_session.Id,
			"sid": str(new_session.Session.Id),
			"from_ip": from_ip,
			"authn_by": login_descriptor,
		})
		await self.LastActivityService.update_last_activity(
			EventCode.LOGIN_SUCCESS, credentials_id, from_ip=from_ip, authn_by=login_descriptor)

		# Delete login session
		await self.AuthenticationService.delete_login_session(login_session.Id)

		return new_session
