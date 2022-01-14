import logging

import asab
import typing

from .providers import create_provider, GenericOAuth2Login

#

L = logging.getLogger(__name__)

#


class ExternalLoginService(asab.Service):

	def __init__(self, app, service_name="seacatauth.ExternalLoginService"):
		super().__init__(app, service_name)

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
