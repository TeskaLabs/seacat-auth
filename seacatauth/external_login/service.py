import logging

import asab
import typing
import pymongo

from .providers import create_provider, GenericOAuth2Login

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

		auth_webui_base_url = asab.Config.get("general", "auth_webui_base_url")
		self.HomeScreenUrl = auth_webui_base_url.rstrip("/")
		self.LoginScreenUrl = "{}/#/login".format(auth_webui_base_url.rstrip("/"))
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

	def get_provider(self, provider_type) -> GenericOAuth2Login:
		return self.Providers.get(provider_type)

	async def initialize(self, app):
		coll = await self.StorageService.collection(self.ExternalLoginCollection)

		# Index all attributes that can be used for locating
		try:
			await coll.create_index(
				[
					("t", pymongo.ASCENDING),
					("s", pymongo.ASCENDING),
				],
				unique=True
			)
		except Exception as e:
			L.warning("{}; fix it and restart the app".format(e))


	async def create(self, credentials_id, provider_type, sub):
		raise NotImplementedError()

	async def list(self, credentials_id):
		raise NotImplementedError()

	async def get_by_sub(self, provider_type, sub):
		raise NotImplementedError()

	async def update(self, provider_type, sub):
		raise NotImplementedError()

	async def delete(self, provider_type, sub):
		raise NotImplementedError()
