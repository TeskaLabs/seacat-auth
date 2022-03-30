import logging
import passlib.pwd

import asab.storage.exceptions

#

L = logging.getLogger(__name__)

#

_provisioning_intro_message = """

SeaCat Auth is running in provisioning mode.

Use the following credentials to log in:

	USERNAME:   {username}
	PASSWORD:   {password}

"""


class ProvisioningService(asab.Service):

	def __init__(self, app, service_name="seacatauth.ProvisioningService"):
		super().__init__(app, service_name)
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.SuperuserName = asab.Config.get("seacatauth:provisioning", "superuser_name")
		self.TenantID = asab.Config.get("seacatauth:provisioning", "tenant")
		self.SuperuserID = None
		self.SuperroleID = asab.Config.get("seacatauth:provisioning", "superrole_id")
		self.CredentialsProviderID = asab.Config.get("seacatauth:provisioning", "credentials_provider_id")

	async def initialize(self, app):
		await super().initialize(app)

		# Create provisioning credentials provider
		self.CredentialsService.create_dict_provider(self.CredentialsProviderID)
		existing_providers = list(self.CredentialsService.CredentialProviders.keys())
		provider = self.CredentialsService.CredentialProviders[self.CredentialsProviderID]

		# Ensure that the provisioning provider is always first
		for existing_provider in existing_providers:
			self.CredentialsService.CredentialProviders.move_to_end(existing_provider)

		# Create provisioning user
		password = passlib.pwd.genword(length=16)
		self.SuperuserID = await provider.create({
			"username": self.SuperuserName,
			"password": password
		})
		L.log(asab.LOG_NOTICE, _provisioning_intro_message.format(username=self.SuperuserName, password=password))

		# Check if provisioning tenant exists
		try:
			tenant_exists = (await self.TenantService.get_tenant(self.TenantID)) is not None
		except KeyError:
			tenant_exists = False

		# Create provisioning tenant
		if not tenant_exists:
			await self.TenantService.create_tenant(self.TenantID)

		# Assign tenant to provisioning user
		await self.TenantService.assign_tenant(self.SuperuserID, self.TenantID)

		# Create superuser role
		assert (await self.RoleService.create(self.SuperroleID) == "OK")
		assert (await self.RoleService.update_resources(
			role_id=self.SuperroleID,
			resources_to_set=["authz:superuser"]
		) == "OK")

		# Assign superuser role to the provisioning user
		await self.RoleService.set_roles(self.SuperuserID, {"*"}, [self.SuperroleID])

	async def finalize(self, app):
		# Clear ALL superuser sessions
		await self.SessionService.delete_sessions_by_credentials_id(self.SuperuserID)

		# Delete superuser role
		await self.RoleService.delete(role_id=self.SuperroleID)

		# Delete provisioning tenant with all its roles and assignments
		tenant_provider = self.TenantService.get_provider()
		await tenant_provider.delete(self.TenantID)

		await super().finalize(app)
