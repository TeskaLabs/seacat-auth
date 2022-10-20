import datetime
import logging
import secrets

import asab
import asab.storage.exceptions
import asab.exceptions
import pymongo

#

L = logging.getLogger(__name__)

#


class RegistrationService(asab.Service):

	RegistrationKeyByteLength = 32
	RegistrationUriFormat = "{auth_webui_base_url}#register?invite={invitation_id}"

	def __init__(self, app, credentials_svc, service_name="seacatauth.RegistrationService"):
		super().__init__(app, service_name)
		self.CredentialsService = credentials_svc
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.CommunicationService = app.get_service("seacatauth.CommunicationService")
		self.AuditService = app.get_service("seacatauth.AuditService")
		self.StorageService = app.get_service("asab.StorageService")

		self.AuthWebUIBaseUrl = asab.Config.get("general", "auth_webui_base_url").rstrip("/")

		self.RegistrationExpiration = asab.Config.getseconds("seacatauth:registration", "registration_expiration")

		self.RegistrationEncrypted = asab.Config.getboolean("seacatauth:registration", "registration_encrypted")
		if self.RegistrationEncrypted:
			raise NotImplementedError("Registration encryption has not been implemented yet.")

		self.SelfRegistrationAllowed = asab.Config.getboolean("seacatauth:registration", "allow_self_registration")
		if self.SelfRegistrationAllowed:
			raise NotImplementedError("Self-registration has not been implemented yet.")

		self.App.PubSub.subscribe("Application.tick/60!", self._on_tick)


	async def _on_tick(self, event_name):
		await self.delete_expired_unregistered_credentials()


	async def draft_credential(
		self,
		credential_data: dict,
		provider_id: str = None,
		tenant: str = None,
		roles: list = None,
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
		:param tenant:
		:type tenant: str
		:param roles:
		:type roles: list
		:param expiration: Number of seconds specifying the expiration of the invitation
		:type expiration: float
		:param invited_by_cid: Credentials ID of the issuer.
		:type invited_by_cid: str
		:param invited_from_ips: IP address(es) of the issuer.
		:type invited_from_ips: list
		:return: The ID of the generated invitation.
		"""
		registration_key = secrets.token_bytes(self.RegistrationKeyByteLength)
		# TODO: Generate a proper encryption key. Registration code is key + signature.
		registration_code = registration_key
		registration_data = {
			"code": registration_code,
			"t": tenant,  # Tenant already validated in the handler
		}

		if invited_by_cid is not None:
			registration_data["ic"] = invited_by_cid

		if invited_from_ips is not None:
			registration_data["ii"] = invited_from_ips

		if roles is not None:
			for role_id in roles:
				role = await self.RoleService.get(role_id)
				if role.get("t") not in (tenant, None):
					raise asab.exceptions.ValidationError()
			registration_data["r"] = roles

		if expiration is None:
			expiration = self.RegistrationExpiration
		expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=expiration)
		registration_data["exp"] = expires_at

		credential_data["suspended"] = True
		credential_data["reg"] = registration_data

		provider = self.get_provider(provider_id)
		credential_id = await provider.create(credential_data)

		L.log(asab.LOG_NOTICE, "Credential drafted", struct_data={
			"credential_id": credential_id,
			"t": tenant,
			"r": roles,
			"invited_by_cid": invited_by_cid,
			"invited_by_ips": invited_from_ips,
		})

		# TODO: Send invitation via mail
		# await self.CommunicationService.registration_link(email=email, registration_uri=registration_uri)
		L.log(asab.LOG_NOTICE, "Sending invitation", struct_data={
			"email": credential_data["email"],
			"invited_by_cid": invited_by_cid,
			"invited_from_ips": invited_from_ips,
			"credential_id": credential_id,
			"registration_uri": self.format_registration_uri(registration_code),
		})

		return credential_id


	async def get_credential_by_registration_code(self, registration_code):
		provider = self.get_provider()
		credentials = await provider.get_by("reg.code", registration_code)
		if credentials["reg"]["exp"] < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("Registration expired")
		return credentials


	async def delete_credential_by_registration_code(self, registration_code):
		provider = self.get_provider()
		credentials = await provider.get_by("reg.code", registration_code)
		await provider.delete(credentials["_id"])
		return credentials


	async def delete_expired_unregistered_credentials(self):
		provider = self.get_provider()
		collection = self.StorageService.Database[provider.CredentialsCollection]
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
		provider = self.get_provider()
		credentials = await provider.get_by("reg.code", registration_code)
		if credentials["reg"]["exp"] < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("Registration expired")
		await provider.update(credentials["_id"], credential_data)


	async def complete_registration(self, registration_code):
		provider = self.get_provider()
		credentials = await provider.get_by("reg.code", registration_code, include=["__pass"])
		# TODO: Proper validation using policy and login descriptors
		if credentials.get("username") in (None, ""):
			raise asab.exceptions.ValidationError("Registration failed: No username.")
		if credentials.get("email") in (None, ""):
			raise asab.exceptions.ValidationError("Registration failed: No email.")
		if credentials.get("__pass") in (None, ""):
			raise asab.exceptions.ValidationError("Registration failed: No password.")
		await provider.update(credentials["_id"], {
			"suspended": False,
			"reg": None
		})
		# TODO: Audit - user registration completed


	def get_provider(self, provider_id: str = None):
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
			if provider.Config.getboolean("registration"):
				return provider
			else:
				L.warning("Provider does not support registration", struct_data={"provider_id": provider_id})
				return None

		# No specific provider requested; get the first one that supports registration
		for provider in self.CredentialsService.CredentialProviders.values():
			if provider.Config.getboolean("registration"):
				return provider
		else:
			L.warning("No credentials provider with enabled registration found")
			return None


	async def invite(
		self,
		tenant: str,
		email: str,
		roles: list = None,
		provider_id: str = None,
		expiration: float = None,
		invited_by_cid: str = None,
		invited_by_ips: str = None,
	):
		"""
		Create an invitation into a tenant and send it to a specified email address.

		:param tenant: The tenant to which the user will be invited
		:type tenant: str
		:param email: The email address of the user to invite
		:type email: str
		:param roles: List of roles to be assigned to the registered user
		:type roles: list
		:param provider_id: The ID of the provider that will be used for registration
		:type provider_id: str
		:param expiration: The expiration time of the invitation in seconds
		:type expiration: float
		:param invited_by_cid: The credential ID of the user who issued the invitation
		:type invited_by_cid: str
		:param invited_by_ips: The IP addresses of the user who issued the invitation
		:type invited_by_ips: str
		:return: The ID of the generated invitation.
		"""

		if expiration is None:
			expiration = self.InviteExpiration

		credential_data = {
			"provider_id": self.get_provider(provider_id),
			"email": email,
			"tenant": tenant,
			"roles": roles,
		}

		# TODO: Validate credential data:
		#   - provider_id exists and supports registration
		#   - tenant exists
		#   - roles exist and match tenant

		invitation_id = await self.create_invitation(
			expiration,
			credential_data=credential_data,
			invited_by_cid=invited_by_cid,
			invited_from_ips=invited_by_ips,
		)

		# TODO: Send invitation via mail
		# await self.CommunicationService.registration_link(email=email, registration_uri=registration_uri)
		L.log(asab.LOG_NOTICE, "Sending invitation", struct_data={
			"email": email,
			"t": tenant,
			"r": roles,
			"invited_by_cid": invited_by_cid,
			"invited_from_ips": invited_by_ips,
			"invitation_id": invitation_id,
			"registration_uri": self.format_registration_uri(invitation_id),
		})

		return invitation_id


	async def self_invite(
		self,
		email: str,
		invited_from_ips: str = None,
	):
		"""
		Request invitation for self-registration.

		:param email: The email address of the user to invite
		:type email: str
		:param invited_from_ips: The IP addresses of the user who requested the invitation
		:type invited_from_ips: str
		:return: The ID of the generated invitation.
		"""

		credential_data = {
			"provider_id": self.get_provider(),
			"email": email,
		}

		invitation_id = await self.create_invitation(
			expiration=self.InviteExpiration,
			credential_data=credential_data,
			invited_from_ips=invited_from_ips,
		)

		# TODO: Send invitation via mail
		# await self.CommunicationService.registration_link(email=email, registration_uri=registration_uri)
		L.log(asab.LOG_NOTICE, "Sending self-invitation", struct_data={
			"email": email,
			"invited_from_ips": invited_from_ips,
			"invitation_id": invitation_id,
			"registration_uri": self.format_registration_uri(invitation_id),
		})

		return invitation_id


	async def create_registration_session(self, invitation_id):
		registration_session_id = secrets.token_urlsafe(self.InvitationCodeByteLength)
		upsertor = self.StorageService.upsertor(self.RegistrationSessionCollection, registration_session_id)

		# TODO: Create key for encrypted registration
		# key = None
		# if self.RegistrationEncrypted:
		# 	key = secrets.token_urlsafe(self.RegistrationKeyByteLength)
		# 	upsertor.set("__k", key, encrypt=True)

		# TODO: Only one registration session per invitation can exist
		upsertor.set("i", invitation_id)

		expires_at = \
			datetime.datetime.now(datetime.timezone.utc) + \
			datetime.timedelta(seconds=self.RegistrationSessionExpiration)
		upsertor.set("exp", expires_at)

		try:
			await upsertor.execute(custom_data={"event_type": "registration_session_created"})
		except asab.storage.exceptions.DuplicateError as e:
			if e.KeyValue is not None and "i" in e.KeyValue:
				raise asab.exceptions.Conflict(
					"Active registration session for this invitation already exists",
					value=e.KeyValue["i"]
				) from e
			else:
				raise ValueError("Falied to create registration session") from e

		L.log(asab.LOG_NOTICE, "Registration session created", struct_data={
			"rsid": registration_session_id,
		})

		return registration_session_id


	async def get_registration_session(self, registration_session_id):
		# TODO: Create RegistrationSession class, similarly to LoginSession
		registration_session = await self.StorageService.get(
			self.RegistrationSessionCollection, registration_session_id, decrypt=["__k"])
		if registration_session["exp"] < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("Expired invitation")
		return registration_session


	async def update_registration_session(self, registration_session_id, **kwargs):
		# TODO: Implement if needed
		raise NotImplementedError()


	async def delete_registration_session(self, registration_session_id):
		await self.StorageService.delete(self.RegistrationSessionCollection, registration_session_id)
		L.log(asab.LOG_NOTICE, "Registration session deleted", struct_data={"rsid": registration_session_id})


	async def delete_expired_registration_sessions(self):
		collection = self.StorageService.Database[self.RegistrationSessionCollection]
		query_filter = {"exp": {"$lt": datetime.datetime.now(datetime.timezone.utc)}}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.log(asab.LOG_NOTICE, "Expired registration sessions deleted", struct_data={
				"count": result.deleted_count})


	async def registration_prologue(self, invitation_id):
		registration_session_id = await self.create_registration_session(invitation_id)
		registration_session = await self.get_registration_session(registration_session_id)


	async def register(self, registration_session_id):
		await self.get_registration_session(registration_session_id)


	async def register_existing_credentials(self, registration_session_id):
		pass


	async def register_new_credentials(self, registration_session_id, register_info: dict):
		"""
		Finalize registration process.

		Scenarios:
		1) User is logged in
			a) Registration token has a tenant
				-> Add the user to the tenant
			b) Registration token has no tenant
				-> Assert that self-registration is open
				-> Let the user create a tenant
		2) User is not logged in
			a) Registration token has a tenant
				-> Create a new user with requested details
				-> Add the user to the tenant
			b) Registration token has no tenant
				-> Invalid request
		"""
		token = await self.get_invitation_detail(token_id)
		token_credentials = token.get("c")
		provider = self.get_provider()
		if provider is None:
			return None
		credentials_id = await provider.register(register_info)

		tenant = token_credentials.get("tenant")
		if tenant is not None:
			await self.TenantService.assign_tenant(credentials_id, tenant)

		roles = token_credentials.get("roles")
		if roles is not None:
			await self.RoleService.set_roles(credentials_id, [tenant], roles)

		return result


	def format_registration_uri(self, invitation_id: str):
		return self.RegistrationUriFormat.format(
			auth_webui_base_url=self.AuthWebUIBaseUrl,
			invitation_id=invitation_id)
