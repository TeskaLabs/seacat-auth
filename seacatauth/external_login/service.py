import datetime
import logging
import secrets
import aiohttp
import typing
import pymongo

import asab
import asab.web.rest

from .providers import create_provider, GenericOAuth2Login
from .. import exceptions, AuditLogger
from ..events import EventTypes
from ..last_activity import EventCode
from ..session import (
	credentials_session_builder,
	authz_session_builder,
	cookie_session_builder,
	authentication_session_builder,
	available_factors_session_builder,
	external_login_session_builder,
	SessionAdapter,
)

#

L = logging.getLogger(__name__)

#


asab.Config.add_defaults({
	"seacatauth:external_login": {
		# URI for the external registration of unknown accounts from external identity providers.
		"registration_webhook_uri": "",
		"state_expiration": "10m",
		"error_redirect_url": ""
	}})


class ExternalLoginService(asab.Service):

	ExternalLoginCollection = "el"
	ExternalLoginStateCollection = "els"

	def __init__(self, app, service_name="seacatauth.ExternalLoginService"):
		super().__init__(app, service_name)

		self.StorageService = app.get_service("asab.StorageService")
		self.SessionService = None
		self.AuthenticationService = None
		self.CredentialsService = None
		self.RegistrationService = None
		self.TenantService = None
		self.RoleService = None
		self.LastActivityService = None

		self.StateExpiration = datetime.timedelta(seconds=asab.Config.getseconds(
			"seacatauth:external_login", "state_expiration"))
		self.RegistrationWebhookUri = asab.Config.get(
			"seacatauth:external_login", "registration_webhook_uri").rstrip("/")
		self.CallbackEndpointPath = "/public/ext-login/{provider_type}"
		self.InitializeLoginEndpointPath = "/public/ext-login/{provider_type}/initialize"

		public_api_base_url = app.PublicSeacatAuthApiUrl
		# TODO: This path must be configurable
		self.CallbackUrl = "{}{}".format(
			public_api_base_url,
			self.CallbackEndpointPath.lstrip("/")
		)
		self.MyAccountPageUrl = "{}#/".format(app.AuthWebUiUrl)
		self.ErrorRedirectUrl = asab.Config.get("seacatauth:external_login", "error_redirect_url")
		if not self.ErrorRedirectUrl:
			self.ErrorRedirectUrl = self.MyAccountPageUrl

		self.Providers: typing.Dict[str, GenericOAuth2Login] = self._prepare_providers()
		self.AcrValues: typing.Dict[str, GenericOAuth2Login] = {
			provider.acr_value(): provider
			for provider in self.Providers.values()}

		app.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)


	async def initialize(self, app):
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.RegistrationService = app.get_service("seacatauth.RegistrationService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.LastActivityService = app.get_service("seacatauth.LastActivityService")

		for provider in self.Providers.values():
			await provider.initialize(app)

		coll = await self.StorageService.collection(self.ExternalLoginCollection)
		await coll.create_index(
			[
				("cid", pymongo.ASCENDING),
			],
		)


	async def _on_housekeeping(self, event_name):
		await self._delete_old_authorization_states()


	def _prepare_providers(self):
		providers = {}
		for section in asab.Config.sections():
			provider = create_provider(self, section)
			if provider is not None:
				providers[provider.Type] = provider
		return providers


	def _make_id(self, provider_type: str, sub: str):
		return "{} {}".format(provider_type, sub)


	def get_provider(self, provider_type: str) -> GenericOAuth2Login:
		return self.Providers.get(provider_type)


	async def prepare_external_login_url(
		self,
		provider: GenericOAuth2Login,
		login_session=None,
		session=None,
	):
		"""
		Prepare the authorization URL of the requested external login provider
		"""
		if not login_session:
			if session:
				if session.Session.ParentSessionId:
					root_session = await self.SessionService.get(session.Session.ParentSessionId)
				else:
					root_session = session
			else:
				root_session = None
			login_session = await self.AuthenticationService.create_login_session(root_session)

		nonce = secrets.token_urlsafe()
		await self.AuthenticationService.initialize_external_login(
			login_session, provider.Type, {"nonce": nonce})

		authorization_url = provider.get_authorize_uri(
			redirect_uri=self.CallbackUrl.format(provider_type=provider.Type),
			state=login_session.Id,
			nonce=nonce
		)
		return authorization_url


	async def create(self, credentials_id: str, provider_type: str, user_info: dict | None = None):
		"""
		Assign an external credential to Seacat Auth credentials
		"""
		sub = str(user_info["sub"])
		upsertor = self.StorageService.upsertor(
			self.ExternalLoginCollection,
			obj_id=self._make_id(provider_type, sub)
		)
		upsertor.set("type", provider_type)
		upsertor.set("sub", sub)
		upsertor.set("cid", credentials_id)

		email = user_info.get("email")
		if email is not None:
			upsertor.set("email", email)

		phone = user_info.get("phone_number")
		if phone is not None:
			upsertor.set("phone", phone)

		username = user_info.get("preferred_username")
		if username is not None:
			upsertor.set("username", username)

		elcid = await upsertor.execute(event_type=EventTypes.EXTERNAL_LOGIN_CREATED)
		L.log(asab.LOG_NOTICE, "External login credential created", struct_data={
			"id": elcid,
			"cid": credentials_id,
		})


	async def list(self, credentials_id: str):
		"""
		List external credentials assigned with Seacat Auth credentials ID
		"""
		collection = self.StorageService.Database[self.ExternalLoginCollection]

		query_filter = {"cid": credentials_id}
		cursor = collection.find(query_filter)

		cursor.sort("_c", -1)

		el_credentials = []
		async for credential in cursor:
			el_credentials.append(credential)

		return el_credentials


	async def get(self, provider_type: str, sub: str):
		"""
		Get external login credential
		"""
		cred = await self.StorageService.get(self.ExternalLoginCollection, self._make_id(provider_type, sub))
		# Back compat fields
		if "e" in cred and "email" not in cred:
			cred["email"] = cred["e"]
		if "s" in cred and "sub" not in cred:
			cred["sub"] = cred["s"]
		if "t" in cred and "type" not in cred:
			cred["type"] = cred["t"]
		return cred


	async def get_by_cid(self, credentials_id: str, provider_type: str):
		"""
		Get external login credential by Seacat Auth credentials ID
		"""
		collection = self.StorageService.Database[self.ExternalLoginCollection]
		query_filter = {"cid": credentials_id, "t": provider_type}
		result = await collection.find_one(query_filter)
		if result is None:
			raise KeyError("External login for type {!r} not registered for credentials".format(provider_type))
		return result


	async def update(self, provider_type, sub):
		raise NotImplementedError()


	async def delete(self, provider_type: str, sub: str, credentials_id: str = None):
		"""
		Remove external login credential
		"""
		if credentials_id is not None:
			el_credential = await self.get(provider_type, sub)
			if credentials_id != el_credential["cid"]:
				raise KeyError("External login not found for these credentials")
		await self.StorageService.delete(self.ExternalLoginCollection, self._make_id(provider_type, sub))
		L.log(asab.LOG_NOTICE, "External login credential deleted", struct_data={
			"type": provider_type,
			"sub": sub,
		})


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


	async def _store_authorization_state(
		self,
		root_session: SessionAdapter | None,
		authorization_query: dict,
		provider_type: str
	) -> (str, str):
		state_id = secrets.token_urlsafe(10)
		nonce = secrets.token_urlsafe(10)
		upsertor = self.StorageService.upsertor(self.ExternalLoginStateCollection, obj_id=state_id)
		upsertor.set("oauth_query", authorization_query)
		upsertor.set("type", provider_type)
		upsertor.set("nonce", nonce)
		if root_session and not root_session.is_anonymous():
			upsertor.set("sid", root_session.SessionId)
			upsertor.set("cid", root_session.Credentials.Id)

		await upsertor.execute()
		return state_id, nonce


	async def pop_authorization_state(self, state_id: str) -> dict:
		coll = await self.StorageService.collection(self.ExternalLoginStateCollection)
		state = await coll.find_one_and_delete({"_id": state_id})
		if state is None:
			raise KeyError("State ID not found: {}".format(state_id))
		return state


	async def _delete_old_authorization_states(self):
		collection = self.StorageService.Database[self.ExternalLoginStateCollection]
		query_filter = {"_c": {"$lt": datetime.datetime.now(datetime.timezone.utc) - self.StateExpiration}}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.info("Expired external login states deleted", struct_data={
				"count": result.deleted_count
			})


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
