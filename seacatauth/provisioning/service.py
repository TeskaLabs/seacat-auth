import json
import logging
import passlib.pwd

import asab.storage.exceptions

#

L = logging.getLogger(__name__)

#

_PROVISIONING_INTRO_MESSAGE = """

SeaCat Auth is running in provisioning mode.

Use the following credentials to log in:

	USERNAME:   {username}
	PASSWORD:   {password}

"""

_PROVISIONING_CONFIG_DEFAULTS = {
	"credentials_name": "provisioning-superuser",
	"credentials_provider_id": "provisioning",
	"role_name": "provisioning-superrole",
	"tenant": "provisioning-tenant",
}


class ProvisioningService(asab.Service):

	def __init__(self, app, service_name="seacatauth.ProvisioningService"):
		super().__init__(app, service_name)
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.ResourceService = app.get_service("seacatauth.ResourceService")

		self.Config = _PROVISIONING_CONFIG_DEFAULTS
		config_file = asab.Config.get("seacatauth:provisioning", "provisioning_config_file").strip() or None
		if config_file is not None:
			with open(config_file) as f:
				self.Config.update(json.load(f))
		self.SuperuserName = self.Config["credentials_name"]
		self.TenantID = self.Config["tenant"]
		self.SuperuserID = None
		self.SuperroleID = "*/{}".format(self.Config["role_name"])
		self.CredentialsProviderID = self.Config["credentials_provider_id"]


	async def initialize(self, app):
		await super().initialize(app)

		# TODO: ResourceService should be already initialized by the app
		await self.ResourceService.initialize(app)

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
		L.log(asab.LOG_NOTICE, _PROVISIONING_INTRO_MESSAGE.format(username=self.SuperuserName, password=password))

		# Create provisioning tenant
		await self.TenantService.create_tenant(self.TenantID)

		# Assign tenant to provisioning user
		await self.TenantService.assign_tenant(self.SuperuserID, self.TenantID)

		# Create superuser role
		await self.RoleService.create(self.SuperroleID)
		assert (await self.RoleService.update_resources(
			role_id=self.SuperroleID,
			resources_to_set=["authz:superuser"]
		) == "OK")

		# Assign superuser role to the provisioning user
		await self.RoleService.assign_role(self.SuperuserID, self.SuperroleID)


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
