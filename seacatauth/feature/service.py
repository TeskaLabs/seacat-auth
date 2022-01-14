import logging

import asab

#

L = logging.getLogger(__name__)

#


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
		do_external_login_uris = [
			{
				"type": provider.Type,
				"authorize_uri": provider.get_login_authorize_uri(),
				"label": provider.Label
			}
			for provider in self.ExternalLoginService.Providers.values()
		]
		if len(do_external_login_uris) > 0:
			login["external"] = do_external_login_uris

		if len(login) > 0:
			features["login"] = login

		# Profile screen elements

		my_account = {}

		add_external_login_uris = [
			{
				"type": provider.Type,
				"authorize_uri": provider.get_addlogin_authorize_uri(),
				"label": provider.Label  # TODO: Separate label for adding the login
			}
			for provider in self.ExternalLoginService.Providers.values()
		]
		if len(add_external_login_uris) > 0:
			my_account["external_login"] = add_external_login_uris

		# TODO: Email, phone etc.

		if len(my_account) > 0:
			features["my_account"] = my_account

		return features
