import datetime
import logging
import secrets

import asab
import asab.storage.exceptions
import asab.exceptions

from ...audit import AuditCode

#

L = logging.getLogger(__name__)

#


class RegistrationService(asab.Service):

	RegistrationKeyByteLength = 32
	RegistrationUriFormat = "{auth_webui_base_url}#register?code={registration_code}"

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

		self.EncryptionEnabled = asab.Config.getboolean("seacatauth:registration", "enable_encryption")
		if self.EncryptionEnabled:
			raise NotImplementedError("Registration encryption has not been implemented yet.")

		self.SelfRegistrationEnabled = asab.Config.getboolean("seacatauth:registration", "enable_self_registration")
		if self.SelfRegistrationEnabled:
			raise NotImplementedError("Self-registration has not been implemented yet.")

		# Support only one registrable credential provider for now
		self.CredentialProvider = self._get_provider()

		# Disable service if there is no registrable provider
		self.Enabled = self.CredentialProvider is not None

		if self.Enabled:
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
		Create new (incomplete) credentials with a registration code

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
		assert self.Enabled
		registration_key = secrets.token_urlsafe(self.RegistrationKeyByteLength)
		# TODO: Generate a proper encryption key. Registration code is random string + key + signature.
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
		credential_data["__registration"] = registration_data

		try:
			credential_id = await self.CredentialProvider.create(credential_data)
		except asab.storage.exceptions.DuplicateError as e:
			if e.KeyValue is not None:
				k, v = e.KeyValue.popitem()
				raise asab.exceptions.Conflict("{} already in use: {}".format(k, v), key=k, value=v)
			else:
				raise asab.exceptions.Conflict()

		await self.AuditService.append(AuditCode.CREDENTIALS_CREATED, {
			"cid": credential_id, "by": invited_by_cid})

		return credential_id, registration_code


	async def get_credential_by_registration_code(self, registration_code):
		"""
		Return the current state of unregistered credentials, including their tenants
		and whether they have a password set

		:param registration_code: The registration code that was sent to the user
		:return: The credential object without sensitive fields
		"""
		assert self.Enabled
		credentials = await self.CredentialProvider.get_by(
			"__registration.code", registration_code, include=["__password", "__registration"])
		if credentials["__registration"]["exp"] < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("Registration expired")

		credentials_public = {
			key: value
			for key, value in credentials.items()
			if key in ["email", "phone", "username"]
		}

		tenants = await self.TenantService.get_tenants(credentials["_id"])
		if tenants is not None:
			credentials_public["tenants"] = tenants

		password_hash = credentials.pop("__password", None)
		credentials_public["password"] = password_hash is not None and len(password_hash) > 0
		# TODO: Add info about configured login factors
		# credentials_public["totp"] = False
		# credentials_public["webauthn"] = False
		# credentials_public["external_login"] = False

		return credentials_public


	async def delete_credential_by_registration_code(self, registration_code: str):
		"""
		Delete credentials by registration code

		:param registration_code: The registration code that was sent to the user
		:type registration_code: str
		"""
		assert self.Enabled
		credentials = await self.CredentialProvider.get_by("__registration.code", registration_code)
		await self.CredentialProvider.delete(credentials["_id"])


	async def delete_expired_unregistered_credentials(self):
		"""
		Delete all credentials that have expired registration time
		"""
		assert self.Enabled
		collection = self.StorageService.Database[self.CredentialProvider.CredentialsCollection]
		query_filter = {"__registration.exp": {"$lt": datetime.datetime.now(datetime.timezone.utc)}}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.log(asab.LOG_NOTICE, "Expired unregistered credentials deleted", struct_data={
				"count": result.deleted_count})


	async def update_credential_by_registration_code(self, registration_code: str, credential_data: dict):
		"""
		Update the credential by registration code

		:param registration_code: The registration code that was sent to the user
		:param credential_data: a dictionary with the update data
		"""
		assert self.Enabled
		for key in credential_data:
			if key not in ["username", "email", "phone", "password"]:
				raise asab.exceptions.ValidationError("Updating '{}' not allowed".format(key))
		credentials = await self.CredentialProvider.get_by(
			"__registration.code", registration_code, include=["__password", "__registration"])
		if credentials["__registration"]["exp"] < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("Registration expired")
		try:
			await self.CredentialProvider.update(credentials["_id"], credential_data)
		except asab.storage.exceptions.DuplicateError as e:
			if e.KeyValue is not None:
				k, v = e.KeyValue.popitem()
				raise asab.exceptions.Conflict("{} already in use: {}".format(k, v), key=k, value=v)
			else:
				raise asab.exceptions.Conflict()


	async def complete_registration(self, registration_code: str):
		"""
		Find the credentials that are associated with the registration code and update them to
		mark them as registered.

		:param registration_code: The registration code that was sent to the user
		"""
		assert self.Enabled
		credentials = await self.CredentialProvider.get_by(
			"__registration.code", registration_code, include=["__password", "__registration"])
		# TODO: Proper validation using policy and login descriptors
		if credentials.get("username") in (None, ""):
			raise asab.exceptions.ValidationError("Registration failed: No username.")
		if credentials.get("email") in (None, ""):
			raise asab.exceptions.ValidationError("Registration failed: No email.")
		if credentials.get("__password") in (None, ""):
			raise asab.exceptions.ValidationError("Registration failed: No password.")
		L.log(asab.LOG_NOTICE, "Credentials registration completed", struct_data={"cid": credentials["_id"]})

		update_dict = {
			"suspended": False,
			"registered": datetime.datetime.now(datetime.timezone.utc),
			"__registration": None  # delete the registration code handle
		}
		if "invited_by" in credentials["__registration"].get("invited_by"):
			update_dict["invited_by"] = credentials["__registration"]["invited_by"]

		await self.CredentialProvider.update(credentials["_id"], update_dict)
		await self.AuditService.append(AuditCode.CREDENTIALS_REGISTERED_NEW, {"cid": credentials["_id"]})


	async def complete_registration_with_existing_credentials(self, registration_code: str, credentials_id: str):
		"""
		Find the credentials associated with the registration code and assign the currently authenticated
		credentials to the tenant and roles associated with the registration code.

		:param registration_code: The registration code that was sent to the user
		:param credentials_id: The ID of the currently authenticated credentials that will be registered
		"""
		assert self.Enabled
		reg_credentials = await self.get_credential_by_registration_code(registration_code)
		reg_credential_id = reg_credentials["_id"]
		reg_tenants = await self.TenantService.get_tenants(reg_credential_id)
		reg_roles = await self.RoleService.get_roles_by_credentials(
			reg_credential_id, reg_tenants)
		for tenant in reg_tenants:
			await self.TenantService.assign_tenant(credentials_id, tenant)
		for role in reg_roles:
			await self.RoleService.assign_role(credentials_id, role)
		await self.CredentialsService.delete_credentials(reg_credential_id)
		L.log(asab.LOG_NOTICE, "Credentials registered to a new tenant", struct_data={
			"cid": credentials_id,
			"reg_cid": reg_credential_id,
			"tenants": ", ".join(reg_tenants),
			"roles": ", ".join(reg_roles),
		})
		await self.AuditService.append(AuditCode.CREDENTIALS_REGISTERED_EXISTING, {
			"cid": credentials_id, "tenants": reg_tenants, "roles": reg_roles})


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


	def format_registration_uri(self, registration_code: str):
		assert self.Enabled
		return self.RegistrationUriFormat.format(
			auth_webui_base_url=self.AuthWebUIBaseUrl,
			registration_code=registration_code)
