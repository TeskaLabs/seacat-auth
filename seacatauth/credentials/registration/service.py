import datetime
import logging
import secrets

import asab

#

L = logging.getLogger(__name__)

#


class RegistrationService(asab.Service):

	InvitationTokenCollection = "it"
	InvitationTokenByteLength = 32
	RegistrationSessionCollection = "rt"
	RegistrationTokenByteLength = 32
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

		self.InviteExpiration = asab.Config.getseconds(
			"seacatauth:registration", "invitation_expiration", fallback=None)
		self.RegistrationSessionExpiration = asab.Config.getseconds(
			"seacatauth:registration", "registration_session_expiration")

		self.RegistrationEncrypted = asab.Config.getboolean("seacatauth:registration", "registration_encrypted")
		if self.RegistrationEncrypted:
			raise NotImplementedError("Registration encryption has not been implemented yet.")

		self.SelfRegistrationAllowed = asab.Config.getboolean("seacatauth:registration", "allow_self_registration")
		if self.SelfRegistrationAllowed:
			raise NotImplementedError("Self-registration has not been implemented yet.")


		self.App.PubSub.subscribe("Application.tick/60!", self._on_tick)


	async def _on_tick(self, event_name):
		await self.delete_expired_invitations()


	async def create_invitation(
		self,
		expiration: float,
		credential_data: dict = None,
		invited_by_cid: str = None,
		invited_by_ips: list = None,
	):
		"""
		Issue a new invitation

		:param credential_data: Details of the user being invited
		:type credential_data: dict
		:param expiration: Number of seconds specifying the expiration of the invitation
		:type expiration: float
		:param invited_by_cid: Credentials ID of the issuer.
		:type invited_by_cid: str
		:param invited_by_ips: IP address(es) of the issuer.
		:type invited_by_ips: list
		:return: The ID of the generated invitation.
		"""
		invitation_id = secrets.token_urlsafe(self.InvitationTokenByteLength)
		upsertor = self.StorageService.upsertor(self.InvitationTokenCollection, invitation_id)

		# TODO: The credential_data should be validated with the registration policy
		# policy = self.CredentialsService.Policy.RegistrationPolicy
		upsertor.set("c", credential_data)

		if invited_by_cid is not None:
			upsertor.set("ic", invited_by_cid)

		if invited_by_ips is not None:
			upsertor.set("ii", invited_by_ips)

		expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=expiration)
		upsertor.set("exp", expires_at)

		await upsertor.execute(custom_data={"event_type": "invitation_created"})

		L.log(asab.LOG_NOTICE, "Invitation created", struct_data={
			"invitation_id": invitation_id,
			"invited_by_cid": invited_by_cid,
			"invited_by_ips": invited_by_ips,
		})

		return invitation_id


	async def get_invitation_detail(self, invitation_id):
		"""
		Retrieve invitation from the database. If it's expired, raise KeyError.

		:param invitation_id: The invitation ID
		:return: Token data.
		"""
		invitation = await self.StorageService.get(self.InvitationTokenCollection, invitation_id)
		if invitation["exp"] < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("Expired invitation")
		return invitation


	async def delete_invitation(self, invitation_id):
		"""
		Delete an invitation from the database

		:param invitation_id: The ID of the invitation
		"""
		await self.StorageService.delete(self.InvitationTokenCollection, invitation_id)
		L.log(asab.LOG_NOTICE, "Invitation deleted", struct_data={"invitation_id": invitation_id})


	async def delete_expired_invitations(self):
		"""
		Delete all expired invitations
		"""
		collection = self.StorageService.Database[self.InvitationTokenCollection]
		query_filter = {"exp": {"$lt": datetime.datetime.now(datetime.timezone.utc)}}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.log(asab.LOG_NOTICE, "Expired invitations deleted", struct_data={
				"count": result.deleted_count})


	async def update_registration_invitation(self, invitation_id, **kwargs):
		# TODO
		raise NotImplementedError()


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
			invited_by_ips=invited_by_ips,
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
			invited_by_ips=invited_from_ips,
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
		registration_session_id = secrets.token_urlsafe(self.InvitationTokenByteLength)
		upsertor = self.StorageService.upsertor(self.RegistrationSessionCollection, registration_session_id)

		# TODO: Create key for encrypted registration
		# key = None
		# if self.RegistrationEncrypted:
		# 	key = secrets.token_urlsafe(self.RegistrationKeyByteLength)
		# 	upsertor.set("__k", key, encrypt=True)

		upsertor.set("i", invitation_id)

		expires_at = \
			datetime.datetime.now(datetime.timezone.utc) + \
			datetime.timedelta(seconds=self.RegistrationSessionExpiration)
		upsertor.set("exp", expires_at)

		await upsertor.execute(custom_data={"event_type": "registration_session_created"})

		L.log(asab.LOG_NOTICE, "Registration session created", struct_data={
			"rsid": registration_session_id,
		})

		return registration_session_id


	async def get_registration_session(self, registration_session_id, **kwargs):
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


	async def register_existing_credentials(self, token_id, register_info: dict):
		pass


	async def register_new_credentials(self, token_id, register_info: dict):
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
