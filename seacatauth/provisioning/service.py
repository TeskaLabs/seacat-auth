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

		# TODO: ResourceService should be already initialized by the app
		resource_svc = app.get_service("seacatauth.ResourceService")
		await resource_svc.initialize(app)

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

		# Create provisioning tenant
		try:
			await self.TenantService.create_tenant(self.TenantID)
		except KeyError:
			L.error("Tenant already exists", struct_data={"tenant": self.TenantID})

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
		# Delete the superuser
		# This also all its sessions and tenant+role assignments
		await self.CredentialsService.delete_credentials(self.SuperuserID)

		# Delete superuser role
		try:
			await self.RoleService.delete(role_id=self.SuperroleID)
		except KeyError:
			L.error("Failed to delete role", struct_data={"role": self.SuperroleID})

		# Delete provisioning tenant with all its roles and assignments
		tenant_provider = self.TenantService.get_provider()
		try:
			await tenant_provider.delete(self.TenantID)
		except KeyError:
			L.error("Failed to delete tenant", struct_data={"tenant": self.TenantID})

		await super().finalize(app)
