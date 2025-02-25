import logging

import asab


L = logging.getLogger(__name__)


class FeatureService(asab.Service):

	def __init__(self, app, service_name="seacatauth.FeatureService"):
		super().__init__(app, service_name)
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.ExternalLoginService = app.get_service("seacatauth.ExternalLoginService")

	async def get_features(self):
		features = {}

		login = {}

		# TODO: Registration options
		registration = []
		if len(registration) > 0:
			features["registration"] = registration

		# External login options
		login_with_external_account_uris = [
			{
				"type": provider.Type,
				"authorize_uri": "{api_base_url}/public/ext-login/{provider_type}/login".format(
					api_base_url=self.App.PublicSeacatAuthApiUrl.rstrip("/"), provider_type=provider.Type),
				"label": provider.Label
			}
			for provider in self.ExternalLoginService.Providers.values()
		]
		if len(login_with_external_account_uris) > 0:
			login["external"] = login_with_external_account_uris

		if len(login) > 0:
			features["login"] = login

		# Profile screen elements

		my_account = {}

		pair_external_account_uris = [
			{
				"type": provider.Type,
				"authorize_uri": "{api_base_url}/public/ext-login/{provider_type}/pair".format(
					api_base_url=self.App.PublicSeacatAuthApiUrl.rstrip("/"), provider_type=provider.Type),
				"label": provider.Label
			}
			for provider in self.ExternalLoginService.Providers.values()
		]
		if len(pair_external_account_uris) > 0:
			my_account["external_login"] = pair_external_account_uris

		# TODO: Email, phone etc.

		if len(my_account) > 0:
			features["my_account"] = my_account

		return features
