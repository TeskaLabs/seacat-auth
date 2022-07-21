import logging

import asab

#

L = logging.getLogger(__name__)

#


class RegistrationService(asab.Service):

	RegistrationTokenCollection = "rg"

	def __init__(self, app, cred_service, service_name="seacatauth.RegistrationService"):
		super().__init__(app, service_name)
		self.CredentialsService = cred_service
		self.CommunicationService = app.get_service("seacatauth.CommunicationService")
		self.AuditService = app.get_service("seacatauth.AuditService")
		self.StorageService = app.get_service("asab.StorageService")

		self.AuthWebUIBaseUrl = asab.Config.get("general", "auth_webui_base_url").rstrip("/")
		self.InviteExpiration = asab.Config.getseconds("seacatauth:registration", "expiration")

	async def register_credentials(self, register_info: dict):
		'''
		This is an anonymous user request to register (create) new credentials
		'''

		# Locate provider
		provider = None
		for p in self.CredentialProviders.values():
			if not p.Config.getboolean('register'):
				continue
			provider = p
			if provider is not None:
				break

		if provider is None:
			L.warning("Registration of new credentials failed")
			return None

		return await provider.register(register_info)
