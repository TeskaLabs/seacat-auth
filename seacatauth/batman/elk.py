import re
import logging

import aiohttp
import asab.config

#

L = logging.getLogger(__name__)

#


# TODO: When credentials are added/updated/deleted, the sync should happen
#       That's to be done using PubSub mechanism

# TODO: Remove users that are managed by us but are removed (use `managed_role` to find these)


class ELKIntegration(asab.config.Configurable):
	'''
	Kibana / ElasticSearch user push compomnent
	'''

	ConfigDefaults = {
		'url': 'http://localhost:9200/',
		'username': 'elastic',
		'password': 'elastic',

		'local_users': 'elastic kibana logstash_system beats_system remote_monitoring_user',

		'mapped_roles_prefixes': '*/elk:',  # Prefix of roles that will be transfered to Kibana

		'managed_role': 'seacat_managed',  # 'flags' users in ElasticSearch/Kibana that is managed by us,
		# There should be a role created in the ElasticSearch that grants no rights
	}


	def __init__(self, batman_svc, config_section_name="batman:elk", config=None):
		super().__init__(config_section_name=config_section_name, config=config)
		self.BatmanService = batman_svc

		username = self.Config.get('username')
		password = self.Config.get('password')
		self.BasicAuth = aiohttp.BasicAuth(username, password)

		self.URL = self.Config.get('url').rstrip('/')

		lu = re.split(r'\s+', self.Config.get('local_users'), flags=re.MULTILINE)
		lu.append(username)

		self.LocalUsers = frozenset(lu)

		batman_svc.App.PubSub.subscribe("Application.tick/60!", self._on_tick)

	async def _on_tick(self, event_name):
		await self.sync_all()

	async def initialize(self):
		await self.sync_all()

	async def sync_all(self):
		cred_svc = self.BatmanService.App.get_service('seacatauth.CredentialsService')
		async for cred in cred_svc.iterate():
			await self.sync(cred)


	async def sync(self, cred: dict):
		username = cred.get('username')
		if username is None:
			# Be defensive
			L.warning("Cannot create user '{}', no username".format(cred))
			return

		if username in self.LocalUsers:
			# Ignore users that are specified as local
			return

		# Get roles
		roles_svc = self.BatmanService.App.get_service('seacatauth.RoleService')
		roles = await roles_svc.get_roles_by_credentials(cred['_id'])

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

		elk_roles = [
			self.Config.get('managed_role'),  # Add a role that marks the user managed by us
		]

		roles_prefixes = re.split(r'\s+', self.Config.get('mapped_roles_prefixes'), flags=re.MULTILINE)
		for role in roles:
			match = None
			for rp in roles_prefixes:
				if role.startswith(rp):
					match = role[len(rp):]
					break
			if match is None:
				continue

			elk_roles.append(match)


		# Roles by tenant
		tenant_svc = self.BatmanService.App.get_service('seacatauth.TenantService')
		if tenant_svc.is_enabled():
			tenants = await tenant_svc.get_tenants(cred['_id'])
			for tenant in tenants:
				elk_roles.append('tenant_{}'.format(tenant))

		json['roles'] = elk_roles

		try:
			async with aiohttp.ClientSession(auth=self.BasicAuth) as session:
				async with session.post('{}/_xpack/security/user/{}'.format(self.URL, username), json=json) as resp:
					if resp.status == 200:
						# Everything is alright here
						pass
					else:
						text = await resp.text()
						L.warning("Failed to create/upadate the user in ElasticSearch:\n{}".format(text[:1000]))

		except Exception:
			L.exception("Error when communicating with ElasticSearch")
