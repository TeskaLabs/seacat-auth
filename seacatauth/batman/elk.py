import contextlib
import re
import ssl
import logging
import typing
import aiohttp
import aiohttp.client_exceptions
import asab.config
import asab.tls

from ..authz import build_credentials_authz

#

L = logging.getLogger(__name__)

#


# TODO: When credentials are added/updated/deleted, the sync should happen
#       That's to be done using PubSub mechanism

# TODO: Remove users that are managed by us but are removed (use `managed_role` to find these)


class ELKIntegration(asab.config.Configurable):
	"""
	Kibana / ElasticSearch user push compomnent
	"""

	ConfigDefaults = {
		"url": "http://localhost:9200",
		"kibana_url": "http://localhost:5601",

		# Basic credentials / API key (mutually exclusive)
		"username": "",
		"password": "",
		"api_key": "",

		# For SSL options such as `cafile`, please refer to the config of asab.tls.SSLContextBuilder

		# List of elasticsearch system users
		# If Seacat Auth has users with one of these usernames, it will not sync them
		# to avoid interfering with kibana system users
		"local_users": "elastic kibana logstash_system beats_system remote_monitoring_user",

		# This role 'flags' users in ElasticSearch/Kibana that is managed by Seacat Auth
		# There should be a role created in the ElasticSearch that grants no rights
		"seacat_user_flag": "seacat_managed",

		# Enable automatic synchronization of Kibana spaces with Seacat tenants
		"enable_space_sync": True
	}

	EssentialKibanaResources = {
		"kibana:access": {
			"description":
				"Read-only access to tenant space in Kibana."},
		"kibana:edit": {
			"description":
				"Read-write access to tenant space in Kibana."},
		"kibana:admin": {
			"role_name": "kibana_admin",
			"description":
				"Grants access to all features in Kibana across all spaces. For more information, see 'kibana_admin' "
				"role in ElasticSearch documentation."},
		"authz:superuser": {
			"role_name": "superuser",
			"description":
				"Grants full access to cluster management and data indices. This role also grants direct read-only "
				"access to restricted indices like .security. A user with the superuser role can impersonate "
				"any other user in the system."},
	}


	def __init__(self, batman_svc, config_section_name="batman:elk", config=None):
		super().__init__(config_section_name=config_section_name, config=config)
		self.BatmanService = batman_svc
		self.App = self.BatmanService.App
		self.CredentialsService = self.App.get_service("seacatauth.CredentialsService")
		self.TenantService = self.App.get_service("seacatauth.TenantService")
		self.RoleService = self.App.get_service("seacatauth.RoleService")
		self.ResourceService = self.App.get_service("seacatauth.ResourceService")

		self.EnableSpaceSync = self.Config.getboolean("enable_space_sync")
		self.KibanaUrl = self.Config.get("kibana_url").rstrip("/")
		self.ElasticSearchUrl = self.Config.get("url").rstrip("/")
		self.Headers = {"kbn-xsrf": "kibana"}

		username = self.Config.get("username")
		password = self.Config.get("password")
		api_key = self.Config.get("api_key")
		if username != "" and api_key != "":
			raise ValueError("Cannot authenticate with both 'api_key' and 'username'+'password'.")
		if username != "":
			self.Headers["Authorization"] = aiohttp.BasicAuth(username, password).encode()
		elif api_key != "":
			self.Headers["Authorization"] = "ApiKey {}".format(api_key)

		self.ResourcePrefix = "kibana:"
		self.DeprecatedResourcePrefix = "elk:"
		self.DeprecatedResourceRegex = re.compile("^elk:")

		self.SeacatUserFlagRole = self.Config.get("seacat_user_flag")

		# Users that will not be synchronized to avoid conflicts with ELK system users
		ignore_usernames = re.split(r"\s+", self.Config.get("local_users"), flags=re.MULTILINE)
		ignore_usernames.append(username)
		self.IgnoreUsernames = frozenset(ignore_usernames)

		self.SSLContextBuilder = asab.tls.SSLContextBuilder(config_section_name)
		if self.ElasticSearchUrl.startswith("https://"):
			self.SSLContext = self.SSLContextBuilder.build(ssl.PROTOCOL_TLS_CLIENT)
		else:
			self.SSLContext = None

		self.App.PubSub.subscribe("Application.init!", self._on_init)
		self.App.PubSub.subscribe("Role.assigned!", self._on_authz_change)
		self.App.PubSub.subscribe("Role.unassigned!", self._on_authz_change)
		self.App.PubSub.subscribe("Role.updated!", self._on_authz_change)
		self.App.PubSub.subscribe("Tenant.created!", self._on_tenant_created)
		self.App.PubSub.subscribe("Tenant.updated!", self._on_tenant_updated)
		self.App.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)


	@contextlib.asynccontextmanager
	async def _elasticsearch_session(self):
		async with aiohttp.TCPConnector(ssl=self.SSLContext or False) as connector:
			async with aiohttp.ClientSession(connector=connector, headers=self.Headers) as session:
				yield session


	async def _on_init(self, event_name):
		await self._initialize_resources()


	async def _on_housekeeping(self, event_name):
		await self._sync_all_tenants_and_spaces()
		await self.sync_all_credentials()


	async def _on_authz_change(self, event_name, credentials_id=None, **kwargs):
		if credentials_id:
			await self.sync_credentials(credentials_id)
		else:
			await self.sync_all_credentials()


	async def _on_tenant_created(self, event_name, tenant_id):
		space_id = self._kibana_space_id_from_tenant_id(tenant_id)
		await self._create_or_update_kibana_space(tenant_id, space_id)


	async def _on_tenant_updated(self, event_name, tenant_id):
		space_id = self._kibana_space_id_from_tenant_id(tenant_id)
		await self._create_or_update_kibana_space(tenant_id, space_id)


	async def _sync_all_tenants_and_spaces(self):
		async for tenant in self.TenantService.iterate():
			space_id = self._kibana_space_id_from_tenant_id(tenant["_id"])
			await self._create_or_update_kibana_space(tenant, space_id)


	async def _create_or_update_kibana_space(self, tenant: str | dict, space_id: str = None):
		"""
		Create a Kibana space for specified tenant or update its metadata if necessary.
		Also create a read-only and a read-write Kibana role for that space.
		"""
		if not self.EnableSpaceSync:
			return

		if isinstance(tenant, str):
			tenant_id = tenant
			tenant = await self.TenantService.get_tenant(tenant_id)
		else:
			tenant_id = tenant["_id"]

		if not space_id:
			space_id = self._kibana_space_id_from_tenant_id(tenant_id)

		try:
			async with self._elasticsearch_session() as session:
				async with session.get("{}/api/spaces/space/{}".format(self.KibanaUrl, space_id)) as resp:
					if resp.status == 404:
						existing_space = None
					elif resp.status == 200:
						existing_space = await resp.json()
					else:
						text = await resp.text()
						L.error(
							"Failed to fetch Kibana tenant space (Server responded with {}):\n{}".format(
								resp.status, text[:1000]),
							struct_data={"space_id": space_id, "tenant_id": tenant_id}
						)
						return
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Failed to fetch Kibana tenant space (Connection error): {}".format(str(e)), struct_data={
				"space_id": space_id, "tenant_id": tenant_id})
			return

		space_update = {}
		if existing_space:
			name = tenant.get("label", tenant_id)
			if existing_space.get("name") != name:
				space_update["name"] = name
			description = tenant.get("description")
			if existing_space.get("description") != description:
				space_update["description"] = description
			if len(space_update) > 0:
				space_update["id"] = space_id
		else:
			space_update = {
				"id": space_id,
				"name": tenant.get("label", tenant_id)
			}
			if "description" in tenant:
				space_update["description"] = tenant["description"]

		if not space_update:
			# No changes
			L.debug("Kibana space metadata up to date", struct_data={
				"space_id": space_id, "tenant_id": tenant_id})
			return

		elif existing_space:
			# Update existing space
			try:
				async with self._elasticsearch_session() as session:
					async with session.put(
						"{}/api/spaces/space/{}".format(self.KibanaUrl, space_id), json=space_update
					) as resp:
						if not (200 <= resp.status < 300):
							text = await resp.text()
							L.error(
								"Failed to update Kibana tenant space (Server responded with {}):\n{}".format(
									resp.status, text[:1000]),
								struct_data={"space_id": space_id, "tenant_id": tenant_id}
							)
			except aiohttp.client_exceptions.ClientConnectionError as e:
				L.error("Failed to update Kibana tenant space (Connection error): {}".format(str(e)), struct_data={
					"space_id": space_id, "tenant_id": tenant_id})
			L.log(asab.LOG_NOTICE, "Kibana space updated", struct_data={"id": space_id, "tenant": tenant_id})
			return

		else:
			# Create new space
			try:
				async with self._elasticsearch_session() as session:
					async with session.post("{}/api/spaces/space".format(self.KibanaUrl), json=space_update) as resp:
						if not (200 <= resp.status < 300):
							text = await resp.text()
							L.error(
								"Failed to create Kibana tenant space (Server responded with {}):\n{}".format(
									resp.status, text[:1000]),
								struct_data={"space_id": space_id, "tenant_id": tenant_id}
							)
							return
			except Exception as e:
				L.error("Failed to create Kibana tenant space (Connection error): {}".format(str(e)), struct_data={
					"space_id": space_id, "tenant_id": tenant_id})
				return
			L.log(asab.LOG_NOTICE, "Kibana space created", struct_data={"id": space_id, "tenant": tenant_id})

			# Create roles for space access
			await self._create_kibana_role(tenant_id, space_id, "read")
			await self._create_kibana_role(tenant_id, space_id, "all")


	async def _create_kibana_role(self, tenant_id: str, space_id: str, privileges: str= "read"):
		assert privileges in {"read", "all"}
		role_name = self._elastic_role_from_tenant(tenant_id, privileges)
		role = {
			# Add all privileges for the new space
			"kibana": [{"spaces": [space_id], "base": [privileges]}]
		}

		try:
			async with self._elasticsearch_session() as session:
				async with session.put(
					"{}/api/security/role/{}".format(self.KibanaUrl, role_name), json=role
				) as resp:
					if resp.status // 100 != 2:
						text = await resp.text()
						L.error("Failed to create Kibana role {!r}:\n{}".format(role_name, text[:1000]))
						return
		except Exception as e:
			L.error("Communication with Kibana produced {}: {}".format(type(e).__name__, str(e)))
			return
		L.log(asab.LOG_NOTICE, "Kibana role created.", struct_data={"name": role_name})


	async def _get_kibana_spaces(self):
		try:
			async with self._elasticsearch_session() as session:
				async with session.get("{}/api/spaces/space".format(self.KibanaUrl)) as resp:
					if resp.status // 100 != 2:
						text = await resp.text()
						L.error("Failed to fetch Kibana spaces:\n{}".format(text[:1000]))
						return
					spaces = await resp.json()
		except Exception as e:
			L.error("Communication with Kibana produced {}: {}".format(type(e).__name__, str(e)))
			return
		return spaces


	async def initialize(self):
		await self._initialize_resources()
		await self.sync_all_credentials()


	async def _initialize_resources(self):
		"""
		Create Seacat Auth resources that grant access to ElasticSearch roles
		"""
		# Create core resources that don't exist yet
		for resource_id, resource in self.EssentialKibanaResources.items():
			try:
				await self.ResourceService.get(resource_id)
			except KeyError:
				await self.ResourceService.create(
					resource_id,
					description=resource.get("description")
				)

	async def sync_all_credentials(self):
		elk_resources = await self.ResourceService.list(query_filter={"_id": self.DeprecatedResourceRegex})
		elk_resources = set(
			resource["_id"]
			for resource in elk_resources["data"]
		)
		try:
			async with self._elasticsearch_session() as session:
				async for cred in self.CredentialsService.iterate():
					await self._sync_credentials(session, cred, elk_resources)
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to Elasticsearch/Kibana: {}".format(str(e)))


	async def sync_credentials(self, credentials_id: str):
		elk_resources = await self.ResourceService.list(query_filter={"_id": self.DeprecatedResourceRegex})
		elk_resources = set(
			resource["_id"]
			for resource in elk_resources["data"]
		)
		cred_svc = self.BatmanService.App.get_service("seacatauth.CredentialsService")
		credentials = await cred_svc.get(credentials_id)
		try:
			async with self._elasticsearch_session() as session:
				await self._sync_credentials(session, credentials, elk_resources)
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to Elasticsearch/Kibana: {}".format(str(e)))

	async def _sync_credentials(self, session: aiohttp.ClientSession, cred: dict, elk_resources: typing.Iterable):
		username = cred.get("username")
		if username is None:
			# Be defensive
			L.info("Cannot create user: No username", struct_data={"cid": cred["_id"]})
			return

		if username in self.IgnoreUsernames:
			return

		elastic_user = {
			"enabled": cred.get("suspended", False) is not True,
			# Generate complex deterministic password
			"password": self.BatmanService.generate_password(cred["_id"]),
			"metadata": {
				# Flag users managed by SeaCat Auth
				"seacatauth": True
			},
		}

		v = cred.get("email")
		if v is not None:
			elastic_user["email"] = v

		v = cred.get("full_name")
		if v is not None:
			elastic_user["full_name"] = v

		elk_roles = {self.SeacatUserFlagRole}  # Add a role that marks users managed by Seacat Auth

		# Get full authorization scope
		assigned_tenants = await self.TenantService.get_tenants(cred["_id"])
		authz = await build_credentials_authz(
			self.TenantService, self.RoleService, cred["_id"], tenants=assigned_tenants)

		# Tenant-scoped resources grant privileges for specific tenant spaces
		for tenant_id, resources in authz.items():
			if "kibana:access" in resources:
				elk_roles.add(self._elastic_role_from_tenant(tenant_id, "read"))
			if "kibana:edit" in resources:
				elk_roles.add(self._elastic_role_from_tenant(tenant_id, "all"))

		# Globally authorized resources grant privileges across all Kibana spaces
		global_authz = frozenset(authz.get("*", frozenset()))
		if "authz:superuser" in global_authz:
			elk_roles.add(self.EssentialKibanaResources["authz:superuser"]["role_name"])
		if "kibana:admin" in global_authz:
			elk_roles.add(self.EssentialKibanaResources["kibana:admin"]["role_name"])

		# BACK COMPAT
		# Map globally authorized Seacat resources prefixed with "elk:" to Elastic roles
		elk_roles.update(
			resource[len(self.DeprecatedResourcePrefix):]
			for resource in global_authz.intersection(elk_resources)
		)

		elastic_user["roles"] = list(elk_roles)

		async with session.post(
			"{}/_xpack/security/user/{}".format(self.ElasticSearchUrl, username),
			json=elastic_user
		) as resp:
			if resp.status // 100 == 2:
				# Everything is alright here
				pass
			else:
				text = await resp.text()
				L.warning(
					"Failed to create/update user in ElasticSearch:\n{}".format(text[:1000]),
					struct_data={"cid": cred["_id"]}
				)


	def _elastic_role_from_tenant(self, tenant: str, privileges: str):
		return "tenant_{}_{}".format(tenant, privileges)


	def _kibana_space_id_from_tenant_id(self, tenant_id: str):
		if tenant_id == "default":
			# "default" is a reserved space name in Kibana
			return "seacat-default"
		# Replace forbidden characters with "--"
		# NOTE: Tenant ID can contain "." while space ID can not
		return re.sub("[^a-z0-9_-]", "--", tenant_id)
