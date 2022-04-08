import re
import logging

import aiohttp
import asab.config

#
from seacatauth.authz import get_credentials_authz

L = logging.getLogger(__name__)

#


# TODO: When credentials are added/updated/deleted, the sync should happen
#       That's to be done using PubSub mechanism

# TODO: Remove users that are managed by us but are removed (use `managed_role` to find these)

_GRAFANA_ADMIN_RESOURCE = "grafana:admin"
_GRAFANA_USER_RESOURCE = "grafana:user"


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
		self.TenantService = self.BatmanService.App.get_service("seacatauth.TenantService")
		self.RoleService = self.BatmanService.App.get_service("seacatauth.RoleService")
		self.RBACService = self.BatmanService.App.get_service("seacatauth.RBACService")
		self.ResourceService = self.BatmanService.App.get_service("seacatauth.ResourceService")

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

	async def _initialize_resources(self):
		try:
			await self.ResourceService.get(_GRAFANA_ADMIN_RESOURCE)
		except KeyError:
			await self.ResourceService.create(
				_GRAFANA_ADMIN_RESOURCE,
				description="Grants admin access to Grafana."
			)
		try:
			await self.ResourceService.get(_GRAFANA_USER_RESOURCE)
		except KeyError:
			await self.ResourceService.create(
				_GRAFANA_USER_RESOURCE,
				description="Grants user access to Grafana."
			)

	async def initialize(self):
		await self._initialize_resources()
		await self.sync_all()


	async def sync_all(self):
		cred_svc = self.BatmanService.App.get_service('seacatauth.CredentialsService')
		async for cred in cred_svc.iterate():
			await self.sync(cred)


	async def sync(self, cred: dict):
		username = cred.get('username')
		if username is None:
			# Be defensive
			L.warning("Cannot create Grafana user: No username", struct_data={
				"cid": cred["_id"]
			})
			return

		if username in self.LocalUsers:
			# Ignore users that are specified as local
			return

		# Get authz dict
		authz = await get_credentials_authz(cred["_id"], self.TenantService, self.RoleService)

		# Grafana roles from SCA resources
		# Use only global "*" roles for now
		if self.RBACService.has_resource_access(authz, "*", [_GRAFANA_ADMIN_RESOURCE]) != "OK" \
			and self.RBACService.has_resource_access(authz, "*", [_GRAFANA_USER_RESOURCE]) != "OK":
			# TODO: BACK COMPAT
			#   Use resources instead of roles! This will be removed
			# >>>>>>>>>>>>>>
			if "*/grafana:grafana_admin" not in authz.get("*", {}) \
				and "*/grafana:grafana_user" not in authz.get("*", {}):
				# <<<<<<<<<<<<<<<<<<<<<<<
				L.warning("Cannot create Grafana user: User has no Grafana resources", struct_data={
					"cid": cred["_id"]
				})
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

		# TODO: Check if user exists
		try:
			async with aiohttp.ClientSession(auth=self.BasicAuth) as session:
				async with session.post('{}/api/admin/users'.format(self.URL), json=json) as resp:
					if resp.status == 200:
						pass
					else:
						text = await resp.text()
						L.warning(
							"Failed to create user in Grafana:\n{}".format(text[:1000]),
							struct_data={"cid": cred["_id"], "status": resp.status}
						)
						return

					# Set admin role if Grafana admin resource is present
					if self.RBACService.has_resource_access(authz, "*", [_GRAFANA_ADMIN_RESOURCE]) == "OK" \
						or "*/grafana:grafana_admin" in authz.get("*", {}):  # TODO: BACK COMPAT, Use resources instead
						response = await resp.json()
						_id = response["id"]
						async with session.put("{}/api/admin/users/{}/permissions".format(self.URL, _id), json={
							"isGrafanaAdmin": True
						}) as resp_role:
							if resp_role.status == 200:
								pass
							else:
								text = await resp_role.text()
								L.warning(
									"Failed to update user permissions in Grafana:\n{}".format(text[:1000]),
									struct_data={"cid": cred["_id"], "status": resp.status}
								)

						# Update role
						async with session.patch("{}/api/org/users/{}".format(self.URL, _id), json={
							"role": "Admin"
						}) as resp_role:
							if resp_role.status == 200:
								pass
							else:
								text = await resp_role.text()
								L.warning(
									"Failed to update user roles in Grafana:\n{}".format(text[:1000]),
									struct_data={"cid": cred["_id"], "status": resp.status}
								)

		except Exception as e:
			L.error(
				"Communication with Grafana produced {}: {}".format(type(e).__name__, str(e)),
				struct_data={"cid": cred["_id"]}
			)
