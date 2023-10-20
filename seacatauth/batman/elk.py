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

		# Resources with this prefix will be mapped to Kibana users as roles
		# E.g.: Resource "elk:kibana-analyst" will be mapped to role "kibana-analyst"
		"resource_prefix": "elk:",

		# This role 'flags' users in ElasticSearch/Kibana that is managed by Seacat Auth
		# There should be a role created in the ElasticSearch that grants no rights
		"seacat_user_flag": "seacat_managed",
	}


	def __init__(self, batman_svc, config_section_name="batman:elk", config=None):
		super().__init__(config_section_name=config_section_name, config=config)
		self.BatmanService = batman_svc
		self.App = self.BatmanService.App
		self.CredentialsService = self.App.get_service("seacatauth.CredentialsService")
		self.TenantService = self.App.get_service("seacatauth.TenantService")
		self.RoleService = self.App.get_service("seacatauth.RoleService")
		self.ResourceService = self.App.get_service("seacatauth.ResourceService")

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

		self.ResourcePrefix = self.Config.get("resource_prefix")
		self.ELKResourceRegex = re.compile("^{}".format(
			re.escape(self.Config.get("resource_prefix"))
		))
		self.ELKSeacatFlagRole = self.Config.get("seacat_user_flag")

		# Users that will not be synchronized to avoid conflicts with ELK system users
		ignore_usernames = re.split(r"\s+", self.Config.get("local_users"), flags=re.MULTILINE)
		ignore_usernames.append(username)
		self.IgnoreUsernames = frozenset(ignore_usernames)

		self.SSLContextBuilder = asab.tls.SSLContextBuilder(config_section_name)
		if self.ElasticSearchUrl.startswith("https://"):
			self.SSLContext = self.SSLContextBuilder.build(ssl.PROTOCOL_TLS_CLIENT)
		else:
			self.SSLContext = None

		self.App.PubSub.subscribe("Application.tick/60!", self._on_tick)
		self.App.PubSub.subscribe("Tenant.created!", self._on_tenant_created)
		self.App.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)


	async def _on_housekeeping(self, event_name):
		await self._sync_tenants_and_spaces()


	@contextlib.asynccontextmanager
	async def _elasticsearch_session(self):
		async with aiohttp.TCPConnector(ssl=self.SSLContext or False) as connector:
			async with aiohttp.ClientSession(connector=connector, headers=self.Headers) as session:
				yield session


	async def _on_tick(self, event_name):
		await self._initialize_resources()
		await self.sync_all_credentials()


	async def _on_tenant_created(self, event_name, tenant_id):
		space_id = await self._create_kibana_space(tenant_id)
		await self._create_kibana_role(tenant_id, space_id)


	async def _sync_tenants_and_spaces(self):
		tenants = await self.TenantService.list_tenant_ids()
		spaces = {
			space["id"] for space in
			await self._get_kibana_spaces()
		}
		for tenant in tenants:
			if tenant in spaces:
				# Tenant space already exists
				continue
			space_id = await self._create_kibana_space(tenant)
			await self._create_kibana_role(tenant, space_id)



	async def _create_kibana_space(self, tenant_id):
		tenant = self.TenantService.get_tenant(tenant_id)
		space_id = self._kibana_space_id_from_tenant(tenant)
		space = {
			"id": tenant_id,  # TODO: Space ID cannot contain "." while tenant_id can!
			"name": tenant.get("label", tenant_id)
		}
		if "description" in tenant:
			space["description"] = tenant["description"]

		try:
			async with self._elasticsearch_session() as session:
				async with session.post("{}/api/spaces/space".format(self.KibanaUrl), json=space) as resp:
					if resp.status // 100 != 2:
						text = await resp.text()
						L.error("Failed to create Kibana space {!r}:\n{}".format(space_id, text[:1000]))
						return
		except Exception as e:
			L.error("Communication with Kibana produced {}: {}".format(type(e).__name__, str(e)))
			return

		L.log(asab.LOG_NOTICE, "Kibana space created.", struct_data={"id": space_id, "tenant": tenant_id})
		return space_id


	async def _create_kibana_role(self, tenant_id, space_id):
		role_name = self._elastic_role_from_tenant(tenant_id)
		role = {
			# Add all privileges for the new space
			"kibana": [{"spaces": [space_id], "base": ["all"]}]
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
		# TODO: Remove resource if its respective kibana role has been removed
		"""
		Fetches roles from ELK and creates a Seacat Auth resource for each one of them.
		"""
		# Fetch ELK roles
		try:
			async with self._elasticsearch_session() as session:
				async with session.get("{}/_xpack/security/role".format(self.ElasticSearchUrl)) as resp:
					if resp.status // 100 != 2:
						text = await resp.text()
						L.error("Failed to fetch ElasticSearch roles:\n{}".format(text[:1000]))
						return
					elk_roles_data = await resp.json()
		except Exception as e:
			L.error("Communication with ElasticSearch produced {}: {}".format(type(e).__name__, str(e)))
			return

		# Fetch SCA resources for the ELK module
		existing_elk_resources = await self.ResourceService.list(query_filter={"_id": self.ELKResourceRegex})
		existing_elk_resources = set(
			resource["_id"]
			for resource in existing_elk_resources["data"]
		)

		# Create resources that don't exist yet
		for role in elk_roles_data.keys():
			resource_id = "{}{}".format(self.ResourcePrefix, role)
			if resource_id not in existing_elk_resources:
				await self.ResourceService.create(
					resource_id,
					description="Grants access to ELK role {!r}.".format(role)
				)

	async def sync_all_credentials(self):
		elk_resources = await self.ResourceService.list(query_filter={"_id": self.ELKResourceRegex})
		elk_resources = set(
			resource["_id"]
			for resource in elk_resources["data"]
		)
		try:
			async with self._elasticsearch_session() as session:
				async for cred in self.CredentialsService.iterate():
					await self._sync_credential(session, cred, elk_resources)
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to Elasticsearch/Kibana: {}".format(str(e)))


	async def sync_credential(self, cred: dict):
		elk_resources = await self.ResourceService.list(query_filter={"_id": self.ELKResourceRegex})
		elk_resources = set(
			resource["_id"]
			for resource in elk_resources["data"]
		)
		try:
			async with self._elasticsearch_session() as session:
				await self._sync_credential(session, cred, elk_resources)
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Cannot connect to Elasticsearch/Kibana: {}".format(str(e)))

	async def _sync_credential(self, session: aiohttp.ClientSession, cred: dict, elk_resources: typing.Iterable):
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

		elk_roles = {self.ELKSeacatFlagRole}  # Add a role that marks users managed by Seacat Auth

		for tenant in await self.TenantService.get_tenants(cred["_id"]):
			elk_roles.add(self._elastic_role_from_tenant(tenant))

		# Get authz dict
		authz = await build_credentials_authz(self.TenantService, self.RoleService, cred["_id"])

		# ELK roles from SCA resources
		# Use only global "*" roles for now
		# TODO: Use tenant-authorized resources instead of global
		user_resources = set(authz.get("*", []))
		if "authz:superuser" in user_resources:
			elk_roles.update(
				resource[len(self.ResourcePrefix):]
				for resource in elk_resources
			)
		else:
			elk_roles.update(
				resource[len(self.ResourcePrefix):]
				for resource in user_resources.intersection(elk_resources)
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


	def _elastic_role_from_tenant(self, tenant):
		return "tenant_{}".format(tenant)


	def _kibana_space_id_from_tenant(self, tenant:str):
		return tenant.replace(".", "-")
