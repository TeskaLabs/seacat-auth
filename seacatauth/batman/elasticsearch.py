import asyncio
import contextlib
import datetime
import re
import ssl
import logging
import typing

import aiohttp
import aiohttp.client_exceptions
import urllib.parse
import random
import asab.config
import asab.tls

from .. import exceptions
from ..models.const import ResourceId
from ..authz import build_credentials_authz


L = logging.getLogger(__name__)


class ElasticSearchIntegration(asab.config.Configurable):
	"""
	ElasticSearch / Kibana authorization and user data synchronization
	"""

	ConfigDefaults = {
		"url": "",

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

		# What indices can be accessed by tenant members. Space-separated. Can use {tenant} variable.
		"tenant_indices": "tenant-{tenant}-*",

		# IDs of Elasticsearch resources
		"elasticsearch_superuser_resource_id": ResourceId.SUPERUSER,  # Superuser access to the entire Elasticsearch cluster

		"elasticsearch_monitoring_resource_id": "elasticsearch:monitoring"
	}


	def __init__(self, batman_svc, config_section_name="batman:elasticsearch", config=None):
		super().__init__(config_section_name=config_section_name, config=config)

		# ES connection parameters should be specified in a config section [elasticsearch]
		if "elasticsearch" in asab.Config:
			self.Config.update(asab.Config["elasticsearch"])

		self.BatmanService = batman_svc
		self.App = self.BatmanService.App
		self.CredentialsService = self.App.get_service("seacatauth.CredentialsService")
		self.TenantService = self.App.get_service("seacatauth.TenantService")
		self.RoleService = self.App.get_service("seacatauth.RoleService")
		self.ResourceService = self.App.get_service("seacatauth.ResourceService")

		if not self.Config.get("url"):
			L.warning("No ElasticSearch URL provided. Batman module will not be active.")
			return

		self.Kibana = KibanaUtils(self.App, config_section_name, config)

		elasticsearch_url = self.Config.get("url")
		self.ElasticSearchNodesUrls = get_url_list(elasticsearch_url)
		if len(self.ElasticSearchNodesUrls) == 0:
			raise ValueError("No ElasticSearch URL has been provided")

		# Authorization: username + password or API-key
		username = self.Config.get("username")
		password = self.Config.get("password")
		api_key = self.Config.get("api_key")

		self.Headers = self._prepare_session_headers(username, password, api_key)

		self.TenantIndices = re.split(r"\s+", self.Config.get("tenant_indices"))
		self.ElasticsearchSuperuserResourceId = self.Config.get("elasticsearch_superuser_resource_id")
		self.MonitoringResourceId = self.Config.get("elasticsearch_monitoring_resource_id")

		self.SeacatUserFlagRole = self.Config.get("seacat_user_flag")
		self.IgnoreUsernames = self._prepare_ignored_usernames()

		if self.ElasticSearchNodesUrls[0].startswith("https://"):
			# Try to build SSL context from either the default or the [elasticsearch] section,
			#   whichever contains SSL config options
			if section_has_ssl_option(config_section_name):
				self.SSLContextBuilder = asab.tls.SSLContextBuilder(config_section_name)
			else:
				self.SSLContextBuilder = asab.tls.SSLContextBuilder("elasticsearch")
			self.SSLContext = self.SSLContextBuilder.build(ssl.PROTOCOL_TLS_CLIENT)
		else:
			self.SSLContext = None

		self.RetrySyncAll: datetime.datetime | None = None

		self.App.PubSub.subscribe("Batman.initialized!", self._on_init)
		self.App.PubSub.subscribe("Role.assigned!", self._on_authz_change)
		self.App.PubSub.subscribe("Role.unassigned!", self._on_authz_change)
		self.App.PubSub.subscribe("Role.updated!", self._on_authz_change)
		self.App.PubSub.subscribe("Tenant.assigned!", self._on_authz_change)
		self.App.PubSub.subscribe("Tenant.unassigned!", self._on_authz_change)
		self.App.PubSub.subscribe("Tenant.created!", self._on_tenant_created)
		self.App.PubSub.subscribe("Tenant.updated!", self._on_tenant_updated)
		self.App.PubSub.subscribe("Credentials.updated!", self._on_authz_change)
		self.App.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)
		self.App.PubSub.subscribe("Application.tick/10!", self._retry_sync)


	@contextlib.asynccontextmanager
	async def _elasticsearch_session(self):
		async with aiohttp.TCPConnector(ssl=self.SSLContext or False) as connector:
			async with aiohttp.ClientSession(connector=connector, headers=self.Headers) as session:
				yield session


	@contextlib.asynccontextmanager
	async def _with_elasticsearch_nodes(self, api_call: typing.Callable[..., typing.Awaitable]):
		for node_url in random.sample(self.ElasticSearchNodesUrls, len(self.ElasticSearchNodesUrls)):
			async with self._elasticsearch_session(base_url=node_url) as session:
				try:
					result = await api_call(session=session)
					yield result
				except (aiohttp.client_exceptions.ClientConnectionError, asyncio.TimeoutError):
					L.debug("ElasticSearch node {} is not reachable, trying another one.".format(node_url))
					continue
		raise aiohttp.client_exceptions.ClientConnectionError(
			"Cannot connect to any of the configured ElasticSearch nodes.")


	async def _on_init(self, event_name):
		await self._initialize_resources()
		# Ensure sync on startup even if housekeeping does not happen; prevent syncing twice
		if not asab.Config.getboolean("housekeeping", "run_at_startup"):
			await self.full_sync()


	async def _on_housekeeping(self, event_name):
		await self.full_sync()


	async def _retry_sync(self, event_name):
		if (self.RetrySyncAll is None) or (datetime.datetime.now(datetime.UTC) < self.RetrySyncAll):
			return
		self.RetrySyncAll = None
		await self.full_sync()


	async def full_sync(self):
		self.RetrySyncAll = None
		try:
			await self._sync_all_index_access_roles()
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to ElasticSearch: {}".format(str(e)))
			self.RetrySyncAll = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=60)
			return
		if self.Kibana.is_enabled():
			try:
				await self.Kibana.sync_all_spaces_and_roles()
			except aiohttp.client_exceptions.ClientConnectionError as e:
				L.error("Cannot connect to Kibana: {}".format(str(e)))
				self.RetrySyncAll = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=60)
				return
		try:
			await self.sync_all_credentials()
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to ElasticSearch: {}".format(str(e)))
			self.RetrySyncAll = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=60)
			return


	async def _on_authz_change(self, event_name, credentials_id=None, **kwargs):
		cred_svc = self.BatmanService.App.get_service("seacatauth.CredentialsService")
		if not credentials_id:
			# No specific credentials ID provided, sync all credentials
			try:
				await self.sync_all_credentials()
			except aiohttp.client_exceptions.ClientConnectionError as e:
				L.error("Cannot connect to ElasticSearch: {}".format(str(e)))
				self.RetrySyncAll = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=60)
			return

		# Sync only the specified credentials
		try:
			credentials = await cred_svc.get(credentials_id)
		except exceptions.CredentialsNotFoundError:
			# The authz update probably happened on deleted credentials
			return

		try:
			async with self._elasticsearch_session() as session:
				await self.sync_credentials(session, credentials)
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to ElasticSearch: {}".format(str(e)))
			self.RetrySyncAll = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=60)
			return



	async def _on_tenant_created(self, event_name, tenant_id):
		try:
			await self._upsert_role_for_index_access(tenant_id, "read")
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to ElasticSearch: {}".format(str(e)))
			self.RetrySyncAll = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=60)
			return

		if self.Kibana.is_enabled():
			await self.Kibana.sync_space_and_roles(tenant_id)


	async def _on_tenant_updated(self, event_name, tenant_id):
		try:
			await self._upsert_role_for_index_access(tenant_id, "read")
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to ElasticSearch: {}".format(str(e)))
			self.RetrySyncAll = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=60)
			return

		if self.Kibana.is_enabled():
			await self.Kibana.sync_space_and_roles(tenant_id)


	async def _sync_all_index_access_roles(self):
		try:
			async for tenant in self.TenantService.iterate():
				# Update Elasticsearch roles with index access privileges
				await self._upsert_role_for_index_access(tenant["_id"], "read")
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to ElasticSearch: {}".format(str(e)))
			self.RetrySyncAll = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=60)
			return


	async def _upsert_role_for_index_access(self, tenant_id: str, privileges: str = "read"):
		assert privileges in {"read", "all"}
		role_name = get_index_access_role_name(tenant_id, privileges)
		required_index_settings = {
			"names": [
				index.format(tenant=tenant_id)
				for index in self.TenantIndices
			],
			"privileges": [privileges],
		}

		try:
			async with self._with_elasticsearch_nodes(
				lambda session: session.get("_security/role/{}".format(role_name))
			) as resp:
				if resp.status == 200:
					role_data = (await resp.json()).get(role_name)
				elif resp.status == 404:
					role_data = None
				else:
					text = await resp.text()
					L.error(
						"Failed to get ElasticSearch role:\n{}".format(text[:1000]),
						struct_data={"code": resp.status, "role": role_name}
					)
					return
		except aiohttp.client_exceptions.ClientConnectionError:
			raise aiohttp.client_exceptions.ClientConnectionError(
				"Cannot connect to any of the configured ElasticSearch nodes.")

		# Check if index privileges are present in role settings
		if role_data and role_data.get("indices"):
			for index_settings in role_data.get("indices"):
				for k, v in required_index_settings.items():
					if v != index_settings.get(k):
						break
				else:
					return

		# Add access to elasticsearch indices
		role_data = {"indices": [required_index_settings]}
		try:
			async with self._with_elasticsearch_nodes(
				lambda session: session.put("_security/role/{}".format(role_name), json=role_data)
			) as resp:
				if not (200 <= resp.status < 300):
					text = await resp.text()
					L.error(
						"Failed to create/update ElasticSearch role:\n{}".format(text[:1000]),
						struct_data={"code": resp.status, "role": role_name}
					)
					return
				result = await resp.json()
		except aiohttp.client_exceptions.ClientConnectionError:
			raise aiohttp.client_exceptions.ClientConnectionError(
				"Cannot connect to any of the configured ElasticSearch nodes.")

		created = result.get("role", {}).get("created")
		if created is True:
			L.info("ElasticSearch role created.", struct_data={"role": role_name})
		else:
			L.info("ElasticSearch role updated.", struct_data={"role": role_name})

		return role_name


	async def initialize(self):
		pass


	async def _initialize_resources(self):
		"""
		Create Seacat Auth resources that are mapped to ElasticSearch and Kibana roles
		"""
		resources = {
			self.ElasticsearchSuperuserResourceId: {
				"description":
					"Grants full access to cluster management and data indices. This role also grants direct read-only "
					"access to restricted indices like .security. A user with the superuser role can impersonate "
					"any other user in the system.",
				"global_only": True,
			},
			self.MonitoringResourceId: {
				"description":
					"Grants access to Elasticsearch Stack monitoring via Elasticsearch role 'monitoring_user'.",
				"global_only": True,
			},
		}
		if self.Kibana.is_enabled():
			resources.update(self.Kibana.get_kibana_resources())

		# Initialize resources that are not initialized yet
		for resource_id, resource_config in resources.items():
			if resource_id in ResourceId:
				# Skip resources that are already managed by Seacat Auth
				continue

			try:
				resource_db = await self.ResourceService.get(resource_id)
			except KeyError:
				await self.ResourceService.create(
					resource_id,
					**resource_config,
					is_managed_by_seacat_auth=True,
				)
				continue

			# Resource exists, check if it needs to be updated
			for k, v in resource_config.items():
				if resource_db.get(k) != v:
					await self.ResourceService._update(
						resource_db,
						**resource_config,
						is_managed_by_seacat_auth=True,
					)
					break


	async def sync_all_credentials(self):
		# TODO: Remove users that are managed by us but are removed (use `managed_role` to find these)
		async with self._elasticsearch_session() as session:
			async for cred in self.CredentialsService.iterate():
				await self.sync_credentials(session, cred)


	async def sync_credentials(self, session: aiohttp.ClientSession, cred: dict):
		username = cred.get("username")
		if username is None:
			# Be defensive
			L.debug("Cannot create user: No username", struct_data={"cid": cred["_id"]})
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

		# Tenant membership grants read access to tenant indices
		for tenant_id, authorized_resources in authz.items():
			if tenant_id == "*":
				# Seacat superuser is mapped to Elasticsearch "superuser" role
				if self.ElasticsearchSuperuserResourceId in authorized_resources:
					elk_roles.add("superuser")
				continue

			if self.MonitoringResourceId in authorized_resources:
				elk_roles.add("monitoring_user")
			elk_roles.add(get_index_access_role_name(tenant_id, "read"))

		# Add roles with Kibana space privileges
		if self.Kibana.is_enabled():
			elk_roles.update(self.Kibana.get_kibana_roles_by_authz(authz))

		elastic_user["roles"] = list(elk_roles)


		try:
			async with self._with_elasticsearch_nodes(
				lambda session: session.post("_xpack/security/user/{}".format(username), json=elastic_user)
			) as resp:
				if 200 <= resp.status < 300:
					# Everything is alright here
					pass
				else:
					text = await resp.text()
					L.warning(
						"Failed to create/update user in ElasticSearch:\n{}".format(text[:1000]),
						struct_data={"cid": cred["_id"]}
					)
		except aiohttp.client_exceptions.ClientConnectionError:
			raise aiohttp.client_exceptions.ClientConnectionError(
				"Cannot connect to any of the configured ElasticSearch nodes.")


	def _prepare_ignored_usernames(self):
		"""
		Load usernames that will not be synchronized to avoid conflicts with ELK system users
		"""
		ignore_usernames = re.split(r"\s+", self.Config.get("local_users"), flags=re.MULTILINE)
		if self.Config.get("username"):
			ignore_usernames.append(self.Config.get("username"))
		return frozenset(ignore_usernames)


	def _prepare_session_headers(self, username, password, api_key):
		headers = {}
		if username != "" and api_key != "":
			raise ValueError("Cannot authenticate with both 'api_key' and 'username'+'password'.")

		if username != "":
			headers["Authorization"] = aiohttp.BasicAuth(username, password).encode()
		elif api_key != "":
			headers["Authorization"] = "ApiKey {}".format(api_key)

		return headers


class KibanaUtils(asab.config.Configurable):
	"""
	Utilities for synchronizing Kibana spaces with Seacat tenants
	and adding Kibana space access to ElasticSearch roles
	"""

	ConfigDefaults = {
		# Enables automatic synchronization of Kibana spaces with Seacat tenants
		# Space sync is disabled if kibana_url is empty.
		"kibana_url": "",

		# IDs of Kibana resources
		"kibana_read_resource_id": "tools:kibana:read",  # Read-only access to tenant space in Kibana
		"kibana_all_resource_id": "tools:kibana:all",  # Read-write access to tenant space in Kibana
		"kibana_admin_resource_id": "tools:kibana:admin",  # Admin access to all of Kibana
	}

	def __init__(self, app, config_section_name="batman:elasticsearch", config=None):
		super().__init__(config_section_name=config_section_name, config=config)

		# ES connection parameters should be specified in a config section [elasticsearch]
		if "elasticsearch" in asab.Config:
			self.Config.update(asab.Config["elasticsearch"])

		self.App = app
		self.TenantService = self.App.get_service("seacatauth.TenantService")

		self.KibanaUrl = self.Config.get("kibana_url").rstrip("/")
		if len(self.KibanaUrl) == 0:
			self.KibanaUrl = None

		# Authorization: username + password or API-key
		username = self.Config.get("username")
		password = self.Config.get("password")
		api_key = self.Config.get("api_key")

		self.Headers = self._prepare_session_headers(username, password, api_key)

		self.ReadResourceId = self.Config.get("kibana_read_resource_id")
		self.AllResourceId = self.Config.get("kibana_all_resource_id")
		self.AdminResourceId = self.Config.get("kibana_admin_resource_id")


	def is_enabled(self):
		return self.KibanaUrl is not None


	def get_kibana_resources(self):
		return {
			self.ReadResourceId: {
				"description": "Read-only access to tenant space in Kibana",
			},
			self.AllResourceId: {
				"description": "Read-write access to tenant space in Kibana",
			},
			self.AdminResourceId: {
				"description":
					"Access to all features in Kibana across all spaces. For more information, see 'kibana_admin' "
					"role in ElasticSearch documentation.",
				"global_only": True,
			},
		}


	def get_kibana_roles_by_authz(self, authz: dict):
		roles = set()
		for tenant_id, authorized_resources in authz.items():
			if tenant_id == "*":
				if self.AdminResourceId in authorized_resources:
					roles.add("kibana_admin")
				continue
			if self.ReadResourceId in authorized_resources:
				roles.add(get_space_access_role_name(tenant_id, "read"))
			if self.AllResourceId in authorized_resources:
				roles.add(get_space_access_role_name(tenant_id, "all"))
		return roles


	@contextlib.asynccontextmanager
	async def _kibana_session(self):
		async with aiohttp.TCPConnector(ssl=False) as connector:
			async with aiohttp.ClientSession(connector=connector, headers=self.Headers) as session:
				yield session


	def _prepare_session_headers(self, username, password, api_key):
		headers = {"kbn-xsrf": "kibana"}

		if username and api_key:
			raise ValueError("Cannot authenticate with both 'api_key' and 'username'+'password'.")

		if username != "":
			headers["Authorization"] = aiohttp.BasicAuth(username, password).encode()
		elif api_key != "":
			headers["Authorization"] = "ApiKey {}".format(api_key)

		return headers


	def space_id_from_tenant_id(self, tenant_id: str):
		if tenant_id == "default":
			# "default" is a reserved space name in Kibana
			return "tenant-default"
		# Replace forbidden characters with "--"
		return re.sub("[^a-z0-9_-]", "--", tenant_id)


	async def upsert_kibana_space(self, tenant: str | dict):
		"""
		Create a Kibana space for specified tenant or update its metadata if necessary.
		"""
		assert self.is_enabled()

		if isinstance(tenant, str):
			tenant_id = tenant
			tenant = await self.TenantService.get_tenant(tenant_id)
		else:
			tenant_id = tenant["_id"]

		space_id = self.space_id_from_tenant_id(tenant_id)

		async with self._kibana_session() as session:
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
			return

		elif existing_space:
			# Update existing space
			async with self._kibana_session() as session:
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
			L.info("Kibana space updated", struct_data={"id": space_id, "tenant": tenant_id})
			return

		else:
			# Create new space
			async with self._kibana_session() as session:
				async with session.post("{}/api/spaces/space".format(self.KibanaUrl), json=space_update) as resp:
					if not (200 <= resp.status < 300):
						text = await resp.text()
						L.error(
							"Failed to create Kibana tenant space (Server responded with {}):\n{}".format(
								resp.status, text[:1000]),
							struct_data={"space_id": space_id, "tenant_id": tenant_id}
						)
						return

			L.info("Kibana space created.", struct_data={"id": space_id, "tenant": tenant_id})


	async def get_kibana_spaces(self):
		assert self.is_enabled()

		async with self._kibana_session() as session:
			async with session.get("{}/api/spaces/space".format(self.KibanaUrl)) as resp:
				if resp.status != 200:
					text = await resp.text()
					L.error("Failed to fetch Kibana spaces:\n{}".format(text[:1000]))
					return
				spaces = await resp.json()
		return spaces


	async def upsert_role_for_space_access(self, tenant_id: str, privileges: str = "read"):
		"""
		Create or update a Kibana role with Kibana space privileges
		@param tenant_id: Tenant whose Kibana space is to be accessed
		@param privileges: "read" for read-only access or "all" for read-write access
		@return:
		"""
		assert self.is_enabled()
		assert privileges in {"read", "all"}

		space_id = self.space_id_from_tenant_id(tenant_id)
		role_name = get_space_access_role_name(tenant_id, privileges)
		required_space_settings = {
			"spaces": [space_id],
			"base": [privileges]
		}

		async with self._kibana_session() as session:
			async with session.get("{}/api/security/role/{}".format(self.KibanaUrl, role_name)) as resp:
				if resp.status == 200:
					role_data = await resp.json()
				elif resp.status == 404:
					role_data = None
				else:
					text = await resp.text()
					L.error("Failed to get ElasticSearch role:\n{}".format(text[:1000]), struct_data={
						"role": role_name})
					return

		# Check if space privileges are present in role settings
		if role_data and role_data.get("kibana"):
			for space_settings in role_data.get("kibana"):
				for k, v in required_space_settings.items():
					if v != space_settings.get(k):
						break
				else:
					return

		# Update space privileges of the role
		if not role_data:
			role_data = {}
		if not role_data.get("kibana"):
			role_data["kibana"] = []
		role = {
			"elasticsearch": role_data.get("elasticsearch", {}),
			"kibana": role_data.get("kibana"),
			"metadata": role_data.get("metadata", {}),
		}
		role["kibana"].append(required_space_settings)
		async with self._kibana_session() as session:
			async with session.put(
				"{}/api/security/role/{}".format(self.KibanaUrl, role_name), json=role
			) as resp:
				if not (200 <= resp.status < 300):
					text = await resp.text()
					L.error("Failed to update role {!r} with Kibana space access privileges:\n{}".format(
						role_name, text[:1000]))
					return

		L.info("Added space access privileges to Kibana role.", struct_data={
			"role": role_name, "space": space_id})


	async def sync_space_and_roles(self, tenant: str | dict):
		"""
		Sync Kibana space with Seacat tenant, add Kibana space access to ElasticSearch roles
		"""
		assert self.is_enabled()

		if isinstance(tenant, str):
			tenant_id = tenant
			tenant = await self.TenantService.get_tenant(tenant_id)
		else:
			tenant_id = tenant["_id"]

		try:
			# Update Kibana space and add space access privileges to roles
			await self.upsert_kibana_space(tenant)
			for privileges in {"read", "all"}:
				await self.upsert_role_for_space_access(tenant_id, privileges)
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to Kibana: {}".format(str(e)))
			return


	async def sync_all_spaces_and_roles(self):
		assert self.is_enabled()

		async for tenant in self.TenantService.iterate():
			await self.sync_space_and_roles(tenant)


def getmultiline(url_string):
	"""
	URL can be a multiline with lines / items devided by spaces
	url=https://localhost:9200 https://localhost:9200 https://localhost:9200
	"""
	return [item.strip() for item in re.split(r"\s+", url_string) if len(item) > 0]


def get_url_list(urls):
	"""
	URLs can devided by a semicolon
	url=https://localhost:9200;localhost:9200;localhost:9200
	"""
	server_urls = []
	if len(urls) > 0:
		urls = getmultiline(urls)
		for url in urls:
			scheme, netloc, path = parse_url(url)

			server_urls += [
				urllib.parse.urlunparse((scheme, netloc, path, None, None, None))
				for netloc in netloc.split(';')
			]

	return server_urls


def parse_url(url):
	parsed_url = urllib.parse.urlparse(url)
	url_path = parsed_url.path
	if not url_path.endswith("/"):
		url_path += "/"

	return parsed_url.scheme, parsed_url.netloc, url_path


def section_has_ssl_option(config_section_name):
	"""
	Checks if at least one of SSL config options (cert, key, cafile, capath, cadata etc.) appears in a config section
	"""
	for item in asab.Config.options(config_section_name):
		if item in asab.tls.SSLContextBuilder.ConfigDefaults:
			return True
	return False


def get_index_access_role_name(tenant: str, privileges: str):
	assert privileges in {"read", "all"}
	return "index_{}_{}".format(tenant, privileges)


def get_space_access_role_name(tenant: str, privileges: str):
	assert privileges in {"read", "all"}
	return "space_{}_{}".format(tenant, privileges)
