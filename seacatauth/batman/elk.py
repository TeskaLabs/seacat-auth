import re
import logging
import typing

import aiohttp
import asab.config

from ..authz import get_credentials_authz

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
		'url': 'http://localhost:9200/',
		'username': 'elastic',
		'password': 'elastic',

		'local_users': 'elastic kibana logstash_system beats_system remote_monitoring_user',

		'mapped_roles_prefixes': '*/elk:',  # Prefix of roles that will be transfered to Kibana

		# Resources with this prefix will be mapped to Kibana users as roles
		# E.g.: Resource "elk:kibana-analyst" will be mapped to role "kibana-analyst"
		"resource_prefix": "elk:",

		'managed_role': 'seacat_managed',  # 'flags' users in ElasticSearch/Kibana that is managed by us,
		# There should be a role created in the ElasticSearch that grants no rights
	}


	def __init__(self, batman_svc, config_section_name="batman:elk", config=None):
		super().__init__(config_section_name=config_section_name, config=config)
		self.BatmanService = batman_svc
		self.CredentialsService = self.BatmanService.App.get_service("seacatauth.CredentialsService")
		self.TenantService = self.BatmanService.App.get_service("seacatauth.TenantService")
		self.RoleService = self.BatmanService.App.get_service("seacatauth.RoleService")
		self.ResourceService = self.BatmanService.App.get_service("seacatauth.ResourceService")

		username = self.Config.get('username')
		password = self.Config.get('password')
		self.BasicAuth = aiohttp.BasicAuth(username, password)

		self.URL = self.Config.get('url').rstrip('/')
		self.ResourcePrefix = self.Config.get("resource_prefix")
		self.ELKResourceRegex = re.compile("^{}".format(
			re.escape(self.Config.get("resource_prefix"))
		))
		self.ELKSeacatFlagRole = self.Config.get("managed_role")

		# TODO: Obsolete, back compat only. Use resources instead of roles.
		#
		self.RolePrefixes = re.split(r"\s+", self.Config.get("mapped_roles_prefixes"))

		lu = re.split(r'\s+', self.Config.get('local_users'), flags=re.MULTILINE)
		lu.append(username)

		self.LocalUsers = frozenset(lu)

		batman_svc.App.PubSub.subscribe("Application.tick/60!", self._on_tick)

	async def _on_tick(self, event_name):
		await self._initialize_resources()
		await self.sync_all()

	async def initialize(self):
		await self._initialize_resources()
		await self.sync_all()

	async def _initialize_resources(self):
		"""
		Fetches roles from ELK and creates a Seacat Auth resource for each one of them.
		"""
		# Fetch ELK roles
		try:
			async with aiohttp.ClientSession(auth=self.BasicAuth) as session:
				async with session.get("{}/_xpack/security/role".format(self.URL)) as resp:
					if resp.status != 200:
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
					description="Grants access to ELK role '{}.".format(role)
				)

	async def sync_all(self):
		elk_resources = await self.ResourceService.list(query_filter={"_id": self.ELKResourceRegex})
		elk_resources = set(
			resource["_id"]
			for resource in elk_resources["data"]
		)
		async for cred in self.CredentialsService.iterate():
			await self.sync(cred, elk_resources)


	async def sync(self, cred: dict, elk_resources: typing.Iterable):
		username = cred.get('username')
		if username is None:
			# Be defensive
			L.info("Cannot create user: No username", struct_data={"cid": cred["_id"]})
			return

		if username in self.LocalUsers:
			# Ignore users that are specified as local
			return

		json = {
			'enabled': cred.get('suspended', False) is not True,

			# Generate technical password
			'password': self.BatmanService.generate_password(cred['_id']),

			'metadata': {
				# We are managed by SeaCat Auth
				'seacatauth': True
			},

		}

		v = cred.get('email')
		if v is not None:
			json['email'] = v

		v = cred.get('full_name')
		if v is not None:
			json['full_name'] = v

		elk_roles = set(
			self.ELKSeacatFlagRole,  # Add a role that marks users managed by Seacat Auth
		)

		# Get authz dict
		authz = await get_credentials_authz(cred["_id"], self.TenantService, self.RoleService)

		# ELK roles from SCA resources
		# Use only global "*" roles for now
		user_resources = set().union(*authz.get("*", {}).values())
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

		# ELK roles from tenants
		for tenant in authz:
			if tenant == "*":
				continue
			elk_roles.add("tenant_{}".format(tenant))

		json["roles"] = list(elk_roles)

		try:
			async with aiohttp.ClientSession(auth=self.BasicAuth) as session:
				async with session.post('{}/_xpack/security/user/{}'.format(self.URL, username), json=json) as resp:
					if resp.status == 200:
						# Everything is alright here
						pass
					else:
						text = await resp.text()
						L.warning(
							"Failed to create/update user in ElasticSearch:\n{}".format(text[:1000]),
							struct_data={"cid": cred["_id"]}
						)
		except Exception as e:
			L.error(
				"Communication with ElasticSearch produced {}: {}".format(type(e).__name__, str(e)),
				struct_data={"cid": cred["_id"]}
			)
