import logging
import aiohttp
import typing
import pymongo

import asab
import asab.web.rest

from .providers import create_provider, GenericOAuth2Login
from ..events import EventTypes

#

L = logging.getLogger(__name__)

#


class ExternalLoginService(asab.Service):

	ExternalLoginCollection = "el"

	def __init__(self, app, service_name="seacatauth.ExternalLoginService"):
		super().__init__(app, service_name)

		self.StorageService = app.get_service("asab.StorageService")
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")

		self.WebhookUrl = asab.Config.get("seacatauth:external_login", "webhook_url").rstrip("/")
		self.AuthUiBaseUrl = asab.Config.get("general", "auth_webui_base_url").rstrip("/")
		self.HomeUiFragmentPath = "/"
		self.LoginUiFragmentPath = "/login"
		self.ExternalLoginPath = "/public/ext-login/{ext_login_provider}"
		self.AddExternalLoginPath = "/public/ext-login-add/{ext_login_provider}"

		self.Providers: typing.Dict[str, GenericOAuth2Login] = self._prepare_providers()


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


	async def initialize(self, app):
		coll = await self.StorageService.collection(self.ExternalLoginCollection)
		await coll.create_index(
			[
				("cid", pymongo.ASCENDING),
			],
		)


	async def create(self, credentials_id: str, provider_type: str, sub: str, email: str = None, ident: str = None):
		upsertor = self.StorageService.upsertor(
			self.ExternalLoginCollection,
			obj_id=self._make_id(provider_type, sub)
		)
		upsertor.set("t", provider_type)
		upsertor.set("s", sub)
		upsertor.set("cid", credentials_id)
		if email is not None:
			upsertor.set("e", email)
		if ident is not None:
			upsertor.set("i", ident)

		elcid = await upsertor.execute(event_type=EventTypes.EXTERNAL_LOGIN_CREATED)
		L.log(asab.LOG_NOTICE, "External login credential created", struct_data={
			"id": elcid,
			"cid": credentials_id,
		})


	async def list(self, credentials_id: str):
		collection = self.StorageService.Database[self.ExternalLoginCollection]

		query_filter = {"cid": credentials_id}
		cursor = collection.find(query_filter)

		cursor.sort("_c", -1)

		el_credentials = []
		async for credential in cursor:
			el_credentials.append(credential)

		return el_credentials


	async def get(self, provider_type: str, sub: str):
		return await self.StorageService.get(self.ExternalLoginCollection, self._make_id(provider_type, sub))


	async def get_sub(self, credentials_id: str, provider_type: str):
		collection = self.StorageService.Database[self.ExternalLoginCollection]
		query_filter = {"cid": credentials_id, "t": provider_type}
		result = await collection.find_one(query_filter)
		if result is None:
			raise KeyError("External login for type '{}' not registered for credentials".format(provider_type))
		return result


	async def update(self, provider_type, sub):
		raise NotImplementedError()


	async def delete(self, provider_type: str, sub: str, credentials_id: str = None):
		if credentials_id is not None:
			el_credential = await self.get(provider_type, sub)
			if credentials_id != el_credential["cid"]:
				raise KeyError("External login not found for these credentials")
		await self.StorageService.delete(self.ExternalLoginCollection, self._make_id(provider_type, sub))
		L.log(asab.LOG_NOTICE, "External login credential deleted", struct_data={
			"type": provider_type,
			"sub": sub,
		})


	async def get_credentials_id_from_webhook(self, provider_type: str, user_info: dict) -> str | None:
		"""
		Inquire about unknown external login credentials from a remote webhook endpoint.
		If the response status is 200 and the JSON body contains 'cid', return its value.
		Otherwise, return None.
		"""
		if self.WebhookUrl is None:
			return None

		request_data = {
			"provider_type": provider_type,
			"user_info": user_info
		}

		async with aiohttp.ClientSession() as session:
			async with session.post(self.WebhookUrl, json=request_data) as resp:
				if resp.status // 100 != 2:
					text = await resp.text()
					L.error("Webhook responded with error.", struct_data={
						"status": resp.status, "text": text})
					return None
				response_data = await resp.json()

		credentials_id = response_data.get("cid")
		if not credentials_id:
			L.error("Webhook response does not contain valid 'cid'.", struct_data={"response_data": response_data})
			return None

		await self.create(
			credentials_id=credentials_id,
			provider_type=provider_type,
			sub=user_info.get("sub"),
			email=user_info.get("email"))

		return credentials_id
