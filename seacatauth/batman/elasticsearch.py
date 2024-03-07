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

from ..authz import build_credentials_authz

#

L = logging.getLogger(__name__)

#


class ElasticSearchIntegration(asab.config.Configurable):
	"""
	ElasticSearch / Kibana authorization and user data synchronization
	"""

	ConfigDefaults = {
		"url": "",

		# Enables automatic synchronization of Kibana spaces with Seacat tenants
		# Space sync is disabled if kibana_url is empty.
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

		# What indices can be accessed by tenant members. Space-separated. Can use {tenant} variable.
		"tenant_indices": "tenant-{tenant}-*",
	}

	EssentialElasticsearchResources = {
		"elasticsearch:access": {
			"description":
				"Read-only access to tenant indices in ElasticSearch and tenant space in Kibana."},
		"elasticsearch:edit": {
			"description":
				"Read-write access to tenant indices in ElasticSearch and tenant space in Kibana."},
		"kibana:access": {  # TODO: OBSOLETE; use "elasticsearch:access"
			"description":
				"Read-only access to tenant space in Kibana."},
		"kibana:edit": {  # TODO: OBSOLETE; use "elasticsearch:edit"
			"description":
				"Read-write access to tenant space in Kibana."},
		"kibana:admin": {  # TODO: OBSOLETE; superuser role is enough
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

		self.Kibana = KibanaUtils(self.App, config_section_name, config)

		self.ElasticSearchUrl = self.Config.get("url")
		self.ElasticSearchNodesUrls = get_url_list(self.ElasticSearchUrl)
		if len(self.ElasticSearchNodesUrls) == 0:
			raise ValueError("No ElasticSearch URL has been provided")

		# Authorization: username + password or API-key
		username = self.Config.get("username")
		password = self.Config.get("password")
		api_key = self.Config.get("api_key")

		self.Headers = self._prepare_session_headers(username, password, api_key)

		self.TenantIndices = re.split(r"\s+", self.Config.get("tenant_indices"))
		self.ResourcePrefix = "kibana:"
		self.DeprecatedResourcePrefix = "elk:"
		self.DeprecatedResourceRegex = re.compile("^elk:")
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
		self.App.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)
		self.App.PubSub.subscribe("Application.tick/10!", self._retry_sync)


	@contextlib.asynccontextmanager
	async def _elasticsearch_session(self):
		async with aiohttp.TCPConnector(ssl=self.SSLContext or False) as connector:
			async with aiohttp.ClientSession(connector=connector, headers=self.Headers) as session:
				yield session


	async def _on_init(self, event_name):
		await self._initialize_resources()
		# Ensure sync on startup even if housekeeping does not happen; prevent syncing twice
		if not asab.Config.getboolean("housekeeping", "run_at_startup"):
			try:
				await self._sync_all_roles_and_spaces()
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


	async def _on_housekeeping(self, event_name):
		try:
			await self._sync_all_roles_and_spaces()
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


	async def _retry_sync(self, event_name):
		if not self.RetrySyncAll or datetime.datetime.now(datetime.UTC) < self.RetrySyncAll:
			return
		self.RetrySyncAll = None
		await self._sync_all_roles_and_spaces()
		await self.sync_all_credentials()


	async def _on_authz_change(self, event_name, credentials_id=None, **kwargs):
		try:
			if credentials_id:
				await self.sync_credentials(credentials_id)
			else:
				await self.sync_all_credentials()
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to ElasticSearch: {}".format(str(e)))
			self.RetrySyncAll = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=60)
			return


	async def _on_tenant_created(self, event_name, tenant_id):
		try:
			for privileges in {"read", "all"}:
				await self._create_or_update_elasticsearch_role(tenant_id, privileges)
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to ElasticSearch: {}".format(str(e)))
			self.RetrySyncAll = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=60)
			return

		if self.Kibana.is_enabled():
			await self.Kibana.sync_space(tenant_id)


	async def _on_tenant_updated(self, event_name, tenant_id):
		try:
			for privileges in {"read", "all"}:
				await self._create_or_update_elasticsearch_role(tenant_id, privileges)
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to ElasticSearch: {}".format(str(e)))
			self.RetrySyncAll = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=60)
			return

		if self.Kibana.is_enabled():
			await self.Kibana.sync_space(tenant_id)


	async def _sync_all_roles_and_spaces(self):
		try:
			async for tenant in self.TenantService.iterate():
				# Update Elasticsearch roles with index privileges
				for privileges in {"read", "all"}:
					await self._create_or_update_elasticsearch_role(tenant["_id"], privileges)
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to ElasticSearch: {}".format(str(e)))
			self.RetrySyncAll = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=60)
			return

		if self.Kibana.is_enabled():
			await self.Kibana.sync_all_spaces()


	async def _create_or_update_elasticsearch_role(self, tenant_id: str, privileges: str = "read"):
		assert privileges in {"read", "all"}
		role_name = elastic_role_from_tenant(tenant_id, privileges)
		required_index_settings = {
			"names": [
				index.format(tenant=tenant_id)
				for index in self.TenantIndices
			],
			"privileges": [privileges],
		}

		async with self._elasticsearch_session() as session:
			async with session.get("{}_security/role/{}".format(self.ElasticSearchUrl, role_name)) as resp:
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

		# Check if index privileges are present in role settings
		if role_data and role_data.get("indices"):
			for index_settings in role_data.get("indices"):
				for k, v in required_index_settings.items():
					if v != index_settings.get(k):
						break
				else:
					L.debug("ElasticSearch role up to date.", struct_data={"role": role_name})
					return

		# Add access to elasticsearch indices
		if not role_data:
			role_data = {}
		if not role_data.get("indices"):
			role_data["indices"] = []
		role_data["indices"].append(required_index_settings)
		async with self._elasticsearch_session() as session:
			async with session.put(
				"{}_security/role/{}".format(self.ElasticSearchUrl, role_name), json=role_data
			) as resp:
				if not (200 <= resp.status < 300):
					text = await resp.text()
					L.error(
						"Failed to create/update ElasticSearch role:\n{}".format(text[:1000]),
						struct_data={"code": resp.status, "role": role_name}
					)
					return
				result = await resp.json()

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
		Create Seacat Auth resources that grant access to ElasticSearch roles
		"""
		# Create core resources that don't exist yet
		for resource_id, resource in self.EssentialElasticsearchResources.items():
			try:
				await self.ResourceService.get(resource_id)
			except KeyError:
				await self.ResourceService.create(
					resource_id,
					description=resource.get("description")
				)

	async def sync_all_credentials(self):
		# TODO: Remove users that are managed by us but are removed (use `managed_role` to find these)
		elk_resources = await self.ResourceService.list(query_filter={"_id": self.DeprecatedResourceRegex})
		elk_resources = set(
			resource["_id"]
			for resource in elk_resources["data"]
		)
		async with self._elasticsearch_session() as session:
			async for cred in self.CredentialsService.iterate():
				await self._sync_credentials(session, cred, elk_resources)


	async def sync_credentials(self, credentials_id: str):
		elk_resources = await self.ResourceService.list(query_filter={"_id": self.DeprecatedResourceRegex})
		elk_resources = set(
			resource["_id"]
			for resource in elk_resources["data"]
		)
		cred_svc = self.BatmanService.App.get_service("seacatauth.CredentialsService")
		credentials = await cred_svc.get(credentials_id)
		async with self._elasticsearch_session() as session:
			await self._sync_credentials(session, credentials, elk_resources)


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
			if "elasticsearch:access" in resources or "kibana:access" in resources:
				elk_roles.add(elastic_role_from_tenant(tenant_id, "read"))
			if "elasticsearch:edit" in resources or "kibana:edit" in resources:
				elk_roles.add(elastic_role_from_tenant(tenant_id, "all"))

		# Globally authorized resources grant privileges across all Kibana spaces
		global_authz = frozenset(authz.get("*", frozenset()))
		if "authz:superuser" in global_authz:
			elk_roles.add(self.EssentialElasticsearchResources["authz:superuser"]["role_name"])
		if "kibana:admin" in global_authz:
			elk_roles.add(self.EssentialElasticsearchResources["kibana:admin"]["role_name"])

		# BACK COMPAT
		# Map globally authorized Seacat resources prefixed with "elk:" to Elastic roles
		elk_roles.update(
			resource[len(self.DeprecatedResourcePrefix):]
			for resource in global_authz.intersection(elk_resources)
		)

		elastic_user["roles"] = list(elk_roles)

		async with session.post(
			"{}_xpack/security/user/{}".format(random.choice(self.ElasticSearchNodesUrls), username),
			json=elastic_user
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


	def is_enabled(self):
		return self.KibanaUrl is not None


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


	def kibana_space_id_from_tenant_id(self, tenant_id: str):
		if tenant_id == "default":
			# "default" is a reserved space name in Kibana
			return "tenant-default"
		# Replace forbidden characters with "--"
		return re.sub("[^a-z0-9_-]", "--", tenant_id)


	async def create_or_update_kibana_space(self, tenant: str | dict, space_id: str = None):
		"""
		Create a Kibana space for specified tenant or update its metadata if necessary.
		"""
		assert self.is_enabled()

		if isinstance(tenant, str):
			tenant_id = tenant
			tenant = await self.TenantService.get_tenant(tenant_id)
		else:
			tenant_id = tenant["_id"]

		if not space_id:
			space_id = self.kibana_space_id_from_tenant_id(tenant_id)

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
			L.debug("Kibana space metadata up to date.", struct_data={
				"space_id": space_id, "tenant_id": tenant_id})
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


	async def add_kibana_space_privileges(self, role_name: str, space_id: str, privileges: str = "read"):
		"""
		Update ElasticSearch role with Kibana space privileges
		@param role_name: ElasticSearch role to be updated
		@param space_id: Kibana space to be accessed
		@param privileges: "read" for read-only access or "all" for read-write access
		@return:
		"""
		assert self.is_enabled()
		assert privileges in {"read", "all"}

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
					L.debug("ElasticSearch role space privileges up to date.", struct_data={"role": role_name})
					return

		# Update space privileges of the role
		if not role_data:
			role_data = {}
		if not role_data.get("kibana"):
			role_data["kibana"] = []
		role = {
			"elasticsearch": role_data.get("elasticsearch"),
			"kibana": role_data.get("kibana", {}),
			"metadata": role_data.get("metadata"),
		}
		role["kibana"].append(required_space_settings)
		async with self._kibana_session() as session:
			async with session.put(
				"{}/api/security/role/{}".format(self.KibanaUrl, role_name), json=role
			) as resp:
				if not (200 <= resp.status < 300):
					text = await resp.text()
					L.error("Failed to update ElasticSearch role {!r} with Kibana space privileges:\n{}".format(
						role_name, text[:1000]))
					return

		L.info("Added Kibana space access to ElasticSearch role.", struct_data={
			"role": role_name, "space": space_id})


	async def sync_space(self, tenant):
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
			# Update Kibana space and add space privileges to roles
			space_id = self.kibana_space_id_from_tenant_id(tenant_id)
			await self.create_or_update_kibana_space(tenant, space_id)
			for privileges in {"read", "all"}:
				role_name = elastic_role_from_tenant(tenant_id, privileges)
				await self.add_kibana_space_privileges(role_name, space_id, privileges)
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to Kibana: {}".format(str(e)))
			return


	async def sync_all_spaces(self):
		assert self.is_enabled()

		async for tenant in self.TenantService.iterate():
			await self.sync_space(tenant)


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


def elastic_role_from_tenant(tenant: str, privileges: str):
	assert privileges in {"read", "all"}
	return "tenant_{}_{}".format(tenant, privileges)
