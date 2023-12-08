import datetime
import logging
import secrets
import aiohttp
import typing
import pymongo

import asab
import asab.web.rest

from .providers import create_provider, GenericOAuth2Login
from ..events import EventTypes
from ..session import SessionAdapter

#

L = logging.getLogger(__name__)

#


asab.Config.add_defaults({
	"seacatauth:external_login": {
		# URI for the external registration of unknown accounts from external identity providers.
		"registration_webhook_uri": "",
		"state_expiration": "10m"
	}})


class ExternalLoginService(asab.Service):

	ExternalLoginCollection = "el"
	ExternalLoginStateCollection = "els"

	def __init__(self, app, service_name="seacatauth.ExternalLoginService"):
		super().__init__(app, service_name)

		self.StorageService = app.get_service("asab.StorageService")
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")

		self.StateExpiration = datetime.timedelta(seconds=asab.Config.getseconds(
			"seacatauth:external_login", "state_expiration"))
		self.RegistrationWebhookUri = asab.Config.get(
			"seacatauth:external_login", "registration_webhook_uri").rstrip("/")
		self.CallbackEndpointPath = "/public/ext-login"

		public_api_base_url = asab.Config.get("general", "public_api_base_url")
		# TODO: This path must be configurable
		self.CallbackUrl = "{}/seacat-auth/{}".format(
			public_api_base_url,
			self.CallbackEndpointPath.lstrip("/")
		)
		auth_webui_url = asab.Config.get("general", "auth_webui_base_url").rstrip("/")
		self.MyAccountPageUrl = "{}/#/".format(auth_webui_url)

		self.Providers: typing.Dict[str, GenericOAuth2Login] = self._prepare_providers()
		self.AcrValues: typing.Dict[str, GenericOAuth2Login] = {
			provider.acr_value(): provider
			for provider in self.Providers.values()}

		app.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)


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
		provider_type: str,
		root_session: SessionAdapter | None,
		authorization_query: dict
	):
		"""
		Prepare the authorization URL of the requested external login provider
		"""
		provider = self.get_provider(provider_type)
		if not provider:
			return None

		state_id, nonce = await self._store_authorization_state(root_session, authorization_query, provider.Type)
		return provider.get_authorize_uri(self.CallbackUrl, state_id, nonce)


	async def initialize(self, app):
		for provider in self.Providers.values():
			await provider.initialize(app)
		coll = await self.StorageService.collection(self.ExternalLoginCollection)
		await coll.create_index(
			[
				("cid", pymongo.ASCENDING),
			],
		)


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


	async def create_new_seacat_auth_credentials(
		self,
		provider_type: str,
		user_info: dict,
		authorization_data: dict,
	) -> str | None:
		"""
		Attempt to create new Seacat Auth credentials for external user.
		"""
		credentials_id = None
		# TODO: Attempt registration with local credential providers if registration is enabled
		try:
			cred_data = {
				"username": user_info.get("preferred_username"),
				"email": user_info.get("email"),
				"phone": user_info.get("phone_number"),
			}
			result = await self.CredentialsService.create_credentials("ext", cred_data)
			credentials_id = result.get("credentials_id")
		except Exception as e:
			L.error(e)

		# Register external user via webhook
		if not credentials_id and self.RegistrationWebhookUri:
			credentials_id = await self.register_credentials_via_webhook(
				provider_type, authorization_data, user_info)

		if credentials_id:
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
		if self.RegistrationWebhookUri is None:
			return None

		request_data = {
			"provider_type": provider_type,
			"authorization_response": authorize_data,
			"user_info": user_info,
		}

		async with aiohttp.ClientSession() as session:
			async with session.post(self.RegistrationWebhookUri, json=request_data) as resp:
				if resp.status not in frozenset([200, 201]):
					text = await resp.text()
					L.error("Webhook responded with error.", struct_data={
						"status": resp.status, "text": text, "url": self.RegistrationWebhookUri})
					return None
				response_data = await resp.json()

		credentials_id = response_data.get("credential_id")
		if not credentials_id:
			L.error("Webhook response does not contain valid 'credential_id'.", struct_data={
				"response_data": response_data})
			return None

		# Test if the ID is reachable
		try:
			await self.CredentialsService.get(credentials_id)
		except KeyError:
			L.error("Returned credential ID not found.", struct_data={"response_data": response_data})
			return None

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
		provider_type: str,
		subject: str,
		root_session: SessionAdapter | None = None,
		from_ip: typing.Iterable | None = None
	) -> dict:
		ext_credentials = await self.get(provider_type, subject)
		credentials_id = ext_credentials["cid"]

		# Create a placeholder login session
		login_descriptors = []
		login_session = await self.AuthenticationService.create_login_session(
			credentials_id=credentials_id,
			client_public_key=None,
			login_descriptors=login_descriptors,
			ident=None
		)

		# Create ad-hoc login descriptor
		login_factor = "ext:{}".format(provider_type)
		login_session.AuthenticatedVia = {
			"id": "!external",
			"label": "Login via {}".format(provider_type),
			"factors": [
				{"id": login_factor, "type": login_factor}
			]
		}

		# Finish login and create session
		# TODO: If there is a valid non-anonymous root session, update it instead of creating a new one
		new_session = await self.AuthenticationService.login(login_session, root_session, from_info=from_ip)
		L.log(asab.LOG_NOTICE, "External login successful", struct_data={
			"cid": credentials_id,
			"login_type": provider_type
		})

		return new_session
