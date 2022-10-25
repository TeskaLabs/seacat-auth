import datetime
import logging
import secrets

import asab
import asab.storage.exceptions
import asab.exceptions

#

L = logging.getLogger(__name__)

#


class RegistrationService(asab.Service):

	RegistrationKeyByteLength = 32
	RegistrationUriFormat = "{auth_webui_base_url}#register?invite={invitation_id}"

	def __init__(self, app, credentials_svc, service_name="seacatauth.RegistrationService"):
		super().__init__(app, service_name)
		self.CredentialsService = credentials_svc
		self.RoleService = None
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.CommunicationService = app.get_service("seacatauth.CommunicationService")
		self.AuditService = app.get_service("seacatauth.AuditService")
		self.StorageService = app.get_service("asab.StorageService")

		self.AuthWebUIBaseUrl = asab.Config.get("general", "auth_webui_base_url").rstrip("/")

		self.RegistrationExpiration = asab.Config.getseconds("seacatauth:registration", "expiration")

		self.RegistrationEncrypted = asab.Config.getboolean("seacatauth:registration", "registration_encrypted")
		if self.RegistrationEncrypted:
			raise NotImplementedError("Registration encryption has not been implemented yet.")

		self.SelfRegistrationAllowed = asab.Config.getboolean("seacatauth:registration", "allow_self_registration")
		if self.SelfRegistrationAllowed:
			raise NotImplementedError("Self-registration has not been implemented yet.")

		# Support only one registrable credential provider for now
		self.CredentialProvider = self._get_provider()

		self.App.PubSub.subscribe("Application.tick/60!", self._on_tick)


	async def initialize(self, app):
		self.RoleService = app.get_service("seacatauth.RoleService")


	async def _on_tick(self, event_name):
		await self.delete_expired_unregistered_credentials()


	async def draft_credentials(
		self,
		credential_data: dict,
		provider_id: str = None,
		expiration: float = None,
		invited_by_cid: str = None,
		invited_from_ips: list = None,
	):
		"""
		Create a new (incomplete) credential with a registration code

		:param credential_data: Details of the user being invited
		:type credential_data: dict
		:param provider_id:
		:type provider_id: str
		:param expiration: Number of seconds specifying the expiration of the invitation
		:type expiration: float
		:param invited_by_cid: Credentials ID of the issuer.
		:type invited_by_cid: str
		:param invited_from_ips: IP address(es) of the issuer.
		:type invited_from_ips: list
		:return: The ID of the generated invitation.
		"""
		registration_key = secrets.token_urlsafe(self.RegistrationKeyByteLength)
		# TODO: Generate a proper encryption key. Registration code is key + signature.
		registration_code = registration_key
		registration_data = {
			"code": registration_code
		}

		if expiration is None:
			expiration = self.RegistrationExpiration
		expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=expiration)
		registration_data["exp"] = expires_at

		if invited_by_cid is not None:
			registration_data["invited_by"] = invited_by_cid

		if invited_from_ips is not None:
			registration_data["invited_from"] = invited_from_ips

		credential_data["suspended"] = True
		credential_data["reg"] = registration_data

		credential_id = await self.CredentialProvider.create(credential_data)

		# TODO: Send invitation via mail
		# await self.CommunicationService.registration_link(email=email, registration_uri=registration_uri)
		L.log(asab.LOG_NOTICE, "Sending invitation", struct_data={
			"email": credential_data["email"],
			"invited_by": invited_by_cid,
			"invited_from": invited_from_ips,
			"credential_id": credential_id,
			"registration_uri": self.format_registration_uri(registration_code),
		})

		return credential_id


	async def get_credential_by_registration_code(self, registration_code):
		credentials = await self.CredentialProvider.get_by("reg.code", registration_code)
		if credentials["reg"]["exp"] < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("Registration expired")
		return credentials


	async def delete_credential_by_registration_code(self, registration_code):
		credentials = await self.CredentialProvider.get_by("reg.code", registration_code)
		await self.CredentialProvider.delete(credentials["_id"])
		return credentials


	async def delete_expired_unregistered_credentials(self):
		collection = self.StorageService.Database[self.CredentialProvider.CredentialsCollection]
		query_filter = {"reg.exp": {"$lt": datetime.datetime.now(datetime.timezone.utc)}}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.log(asab.LOG_NOTICE, "Expired unregistered credentials deleted", struct_data={
				"count": result.deleted_count})


	async def update_credential_by_registration_code(self, registration_code, credential_data):
		if "reg" in credential_data:
			raise asab.exceptions.ValidationError("Registration failed: No username.")
		if "suspended" in credential_data:
			raise asab.exceptions.ValidationError("Cannot unsuspend credential whose registration has not been completed.")
		credentials = await self.CredentialProvider.get_by("reg.code", registration_code)
		if credentials["reg"]["exp"] < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("Registration expired")
		await self.CredentialProvider.update(credentials["_id"], credential_data)


	async def complete_registration(self, registration_code):
		credentials = await self.CredentialProvider.get_by("reg.code", registration_code, include=["__pass"])
		# TODO: Proper validation using policy and login descriptors
		if credentials.get("username") in (None, ""):
			raise asab.exceptions.ValidationError("Registration failed: No username.")
		if credentials.get("email") in (None, ""):
			raise asab.exceptions.ValidationError("Registration failed: No email.")
		if credentials.get("__pass") in (None, ""):
			raise asab.exceptions.ValidationError("Registration failed: No password.")
		await self.CredentialProvider.update(credentials["_id"], {
			"suspended": False,
			"reg": None
		})
		# TODO: Audit - user registration completed


	def _get_provider(self, provider_id: str = None):
		"""
		Locate a provider that supports credentials registration

		:param provider_id: The ID of the provider to use. If not specified, the first
		provider that supports registration will be used
		:type provider_id: str
		:return: A provider object
		"""
		# Specific provider requested
		if provider_id is not None:
			provider = self.CredentialsService.Providers.get(provider_id)
			if provider.RegistrationEnabled:
				return provider
			else:
				L.warning("Provider does not support registration", struct_data={"provider_id": provider_id})
				return None

		# No specific provider requested; get the first one that supports registration
		for provider in self.CredentialsService.CredentialProviders.values():
			if provider.RegistrationEnabled:
				return provider
		else:
			L.warning("No credentials provider with enabled registration found")
			return None


	def format_registration_uri(self, invitation_id: str):
		return self.RegistrationUriFormat.format(
			auth_webui_base_url=self.AuthWebUIBaseUrl,
			invitation_id=invitation_id)
