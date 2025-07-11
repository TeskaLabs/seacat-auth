import json
import logging
import urllib.parse
import secrets
import asab.exceptions
import asab.contextvars
import asab.storage.exceptions

from ..client.schema import CLIENT_TEMPLATES
from ..api import local_authz
from ..models.const import ResourceId


L = logging.getLogger(__name__)


_PROVISIONING_INTRO_MESSAGE = """

SeaCat Auth is running in provisioning mode.

Use the following credentials to log in:

	USERNAME:   {username}
	PASSWORD:   {password}

"""

_PROVISIONING_CONFIG_DEFAULTS = {
	"credentials_name": "provisioning-superuser",
	"credentials_provider_id": "provisioning",
	"role_name": "superuser",
	"tenant": "provisioningtenant",
	"admin_ui_url": "",
	"admin_ui_client_id": "asab-webui-auth",
	"admin_ui_client_name": "ASAB WebUI",
	"redirect_uri_validation_method": "prefix_match",
}


class ProvisioningService(asab.Service):

	def __init__(self, app, service_name="seacatauth.ProvisioningService"):
		super().__init__(app, service_name)
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.ResourceService = app.get_service("seacatauth.ResourceService")
		self.ClientService = app.get_service("seacatauth.ClientService")
		self.SessionService = app.get_service("seacatauth.SessionService")

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
		await self.RoleService.initialize(app)
		await self.ClientService.initialize(app)

		with local_authz(self.Name, resources={ResourceId.SUPERUSER}):
			await self._set_up_provisioning(app)


	async def finalize(self, app):
		with local_authz(self.Name, resources={ResourceId.SUPERUSER}):
			await self._tear_down_provisioning(app)
		await super().finalize(app)


	async def _set_up_provisioning(self, app):
		# Create provisioning credentials provider
		self.CredentialsService.create_dict_provider(self.CredentialsProviderID)
		existing_providers = list(self.CredentialsService.CredentialProviders.keys())
		provider = self.CredentialsService.CredentialProviders[self.CredentialsProviderID]

		# Ensure that the provisioning provider is always first
		for existing_provider in existing_providers:
			self.CredentialsService.CredentialProviders.move_to_end(existing_provider)

		# Create provisioning user
		password = secrets.token_urlsafe(16)
		self.SuperuserID = await provider.create({
			"username": self.SuperuserName,
			"password": password
		})
		L.log(asab.LOG_NOTICE, _PROVISIONING_INTRO_MESSAGE.format(username=self.SuperuserName, password=password))

		# Create provisioning tenant
		try:
			await self.TenantService.create_tenant(self.TenantID)
		except asab.exceptions.Conflict:
			L.log(asab.LOG_NOTICE, "Tenant already exists.", struct_data={"tenant": self.TenantID})

		with asab.contextvars.tenant_context(self.TenantID):
			# Assign tenant to provisioning user
			try:
				await self.TenantService.assign_tenant(self.SuperuserID, self.TenantID)
			except asab.exceptions.Conflict:
				L.log(asab.LOG_NOTICE, "Tenant already assigned.", struct_data={
					"cid": self.SuperuserID, "tenant": self.TenantID})

			# Assign superuser role to the provisioning user
			try:
				await self.RoleService.assign_role(self.SuperuserID, self.SuperroleID)
			except asab.exceptions.Conflict:
				L.log(asab.LOG_NOTICE, "Role already assigned.", struct_data={
					"cid": self.SuperuserID, "role": self.SuperroleID})

		await self._initialize_admin_ui_client()


	async def _tear_down_provisioning(self, app):
		# Delete the superuser
		# This also all its sessions and tenant+role assignments
		await self.CredentialsService.delete_credentials(self.SuperuserID)

		# Delete provisioning tenant with all its roles and assignments
		tenant_provider = self.TenantService.get_provider()
		try:
			await tenant_provider.delete(self.TenantID)
		except KeyError:
			L.error("Tenant already deleted.", struct_data={"tenant": self.TenantID})

		await super().finalize(app)


	async def _initialize_admin_ui_client(self):
		"""
		Registers/updates the ASAB web UI client.
		"""
		admin_ui_client_id = self.Config["admin_ui_client_id"]
		admin_ui_url = self.Config["admin_ui_url"].rstrip("/") or None
		if admin_ui_url is None:
			auth_webui_base_url = self.App.AuthWebUiUrl
			url = urllib.parse.urlparse(auth_webui_base_url)
			# Use the base URL without path by default, to fit all common deployments
			admin_ui_url = url._replace(path="", fragment="", query="", params="").geturl()
			L.log(
				asab.LOG_NOTICE,
				"'admin_ui_url' not specified in provisioning config. Defaulting to '{}'.".format(admin_ui_url)
			)

		try:
			client = await self.ClientService.get_client(admin_ui_client_id)
		except KeyError:
			client = None

		# Configure admin_ui_client as a public web application
		update = {
			k: v
			for k, v in CLIENT_TEMPLATES["Public web application"].items()
		}

		# Check if the client has the correct redirect URI
		if client is None:
			redirect_uris = set()
		else:
			redirect_uris = set(client.get("redirect_uris", []))

		if admin_ui_url not in redirect_uris:
			redirect_uris.add(admin_ui_url)
			update["redirect_uris"] = list(redirect_uris)

		update["client_uri"] = admin_ui_url
		update["redirect_uri_validation_method"] = self.Config["redirect_uri_validation_method"]
		update["client_name"] = self.Config["admin_ui_client_name"]

		if client is None:
			await self.ClientService.create_client(_custom_client_id=admin_ui_client_id, **update)
		elif update:
			await self.ClientService.update_client(client_id=admin_ui_client_id, **update)
