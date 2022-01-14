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


class GrafanaIntegration(asab.config.Configurable):
	'''
	Grafana user push compomnent
	'''

	ConfigDefaults = {
		'url': 'http://localhost:3000/',
		'username': 'admin',
		'password': 'admin',
		'local_users': 'admin',
	}


	def __init__(self, batman_svc, config_section_name="batman:grafana", config=None):
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

		# Check roles
		roles_svc = self.BatmanService.App.get_service('seacatauth.RoleService')
		roles = await roles_svc.get_roles_by_credentials(cred['_id'])
		if "*/grafana:grafana_admin" not in roles and "*/grafana:grafana_user" not in roles:
			L.warning("Cannot create user '{}', roles '{}', no admin rights".format(cred, roles))
			return

		json = {
			'login': username,

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
			json['name'] = v

		try:

			async with aiohttp.ClientSession(auth=self.BasicAuth) as session:
				async with session.post('{}/api/admin/users'.format(self.URL), json=json) as resp:
					if resp.status == 200:

						# Everything is alright here
						if "*/grafana:grafana_admin" in roles:
							response = await resp.json()
							_id = response["id"]
							async with session.put('{}/api/admin/users/{}/permissions'.format(self.URL, _id), json={
								"isGrafanaAdmin": True
							}) as resp_role:
								if resp_role.status == 200:
									pass
								else:
									text = await resp_role.text()
									L.warning("Failed to update user permissions in Grafana:\n{}".format(text[:1000]))

							# Update role
							async with session.patch('{}/api/org/users/{}'.format(self.URL, _id), json={
								"role": "Admin"
							}) as resp_role:
								if resp_role.status == 200:
									pass
								else:
									text = await resp_role.text()
									L.warning("Failed to update user roles in Grafana:\n{}".format(text[:1000]))

					else:
						text = await resp.text()
						L.warning("Failed to create the user in Grafana:\n{}".format(text[:1000]))

		except Exception as e:
			L.exception("Error when communicating with Grafana: '{}'.".format(e))
