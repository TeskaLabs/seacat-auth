import re
import logging
import aiohttp
import aiohttp.client_exceptions
import asab
import asab.config

from seacatauth.authz import build_credentials_authz

#

L = logging.getLogger(__name__)

#

# TODO: Remove users that are managed by us but are removed (use `managed_role` to find these)

_GRAFANA_ADMIN_RESOURCE = "grafana:admin"
_GRAFANA_USER_RESOURCE = "grafana:user"


class GrafanaIntegration(asab.config.Configurable):
	"""
	Grafana user push compomnent
	"""

	ConfigDefaults = {
		"url": "http://localhost:3000/",
		"username": "admin",
		"password": "admin",
		"local_users": "admin",
	}


	def __init__(self, batman_svc, config_section_name="batman:grafana", config=None):
		super().__init__(config_section_name=config_section_name, config=config)
		asab.LogObsolete.warning(
			"Batman for Grafana is deprecated. Please use Grafana generic OAuth instead.",
			struct_data={"eol": "2024-12-31"})
		self.BatmanService = batman_svc
		self.TenantService = self.BatmanService.App.get_service("seacatauth.TenantService")
		self.RoleService = self.BatmanService.App.get_service("seacatauth.RoleService")
		self.RBACService = self.BatmanService.App.get_service("seacatauth.RBACService")
		self.ResourceService = self.BatmanService.App.get_service("seacatauth.ResourceService")

		username = self.Config.get("username")
		password = self.Config.get("password")
		if username != "":
			self.Authorization = aiohttp.BasicAuth(username, password)
		else:
			self.Authorization = None

		self.URL = self.Config.get("url").rstrip("/")

		lu = re.split(r"\s+", self.Config.get("local_users"), flags=re.MULTILINE)
		lu.append(username)

		self.LocalUsers = frozenset(lu)

		batman_svc.App.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)
		batman_svc.App.PubSub.subscribe("Role.assigned!", self._on_authz_change)
		batman_svc.App.PubSub.subscribe("Role.unassigned!", self._on_authz_change)
		batman_svc.App.PubSub.subscribe("Role.updated!", self._on_authz_change)

	async def _on_housekeeping(self, event_name):
		await self.sync_all()

	async def _on_authz_change(self, event_name, credentials_id=None, **kwargs):
		if credentials_id:
			await self.sync_credentials(credentials_id)
		else:
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
		# Ensure sync on startup even if housekeeping does not happen; prevent syncing twice
		if not asab.Config.getboolean("housekeeping", "run_at_startup"):
			await self.sync_all()


	async def sync_all(self):
		"""
		Synchronize all Seacat credentials' metadata and relevant access rights to Grafana user

		Args:
			credential_id: Seacat Auth credential ID
		"""
		cred_svc = self.BatmanService.App.get_service("seacatauth.CredentialsService")
		try:
			async with aiohttp.ClientSession(auth=self.Authorization) as session:
				async for cred in cred_svc.iterate():
					await self._sync_credentials(session, cred)
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Failed to sync Grafana users (Connection error): {}".format(str(e)))


	async def sync_credentials(self, credentials_id: str):
		"""
		Synchronize a single Seacat credential metadata and relevant access rights to Grafana user

		Args:
			credentials_id: Seacat Auth credential ID
		"""
		cred_svc = self.BatmanService.App.get_service("seacatauth.CredentialsService")
		credentials = await cred_svc.get(credentials_id)
		try:
			async with aiohttp.ClientSession(auth=self.Authorization) as session:
				await self._sync_credentials(session, credentials)
		except aiohttp.client_exceptions.ClientConnectionError as e:
			L.error("Failed to sync Grafana user (Connection error): {}".format(str(e)), struct_data={
				"cid": credentials_id})


	async def _sync_credentials(self, session: aiohttp.ClientSession, credentials: dict):
		"""
		Propagate Seacat credential metadata and relevant access rights to Grafana

		Args:
			session: Grafana connection session
			credentials: Seacat credentials dictionary
		"""
		username = credentials.get("username")
		if username is None:
			# Be defensive
			L.info("Cannot create Grafana user: No username", struct_data={
				"cid": credentials["_id"]
			})
			return

		if username in self.LocalUsers:
			# Ignore users that are specified as local
			return

		# Get authz dict
		authz = await build_credentials_authz(self.TenantService, self.RoleService, credentials["_id"])

		# Grafana roles from SCA resources
		# Use only global "*" roles for now
		if not self.RBACService.has_resource_access(authz, "*", [_GRAFANA_ADMIN_RESOURCE]) \
			and not self.RBACService.has_resource_access(authz, "*", [_GRAFANA_USER_RESOURCE]):
			return

		grafana_user = {
			"login": username,

			# Generate technical password
			"password": self.BatmanService.generate_password(credentials["_id"]),

			"metadata": {
				# We are managed by SeaCat Auth
				"seacatauth": True
			},
		}

		v = credentials.get("email")
		if v is not None:
			grafana_user["email"] = v

		v = credentials.get("full_name")
		if v is not None:
			grafana_user["name"] = v

		# TODO: Check if user exists
		async with session.post("{}/api/admin/users".format(self.URL), json=grafana_user) as resp:
			if resp.status == 200:
				pass
			elif resp.status == 412:
				# User already exists
				L.debug(
					"Grafana user already exists",
					struct_data={"cid": credentials["_id"], "status": resp.status})
				return
			else:
				text = await resp.text()
				L.warning(
					"Failed to create user in Grafana:\n{}".format(text[:1000]),
					struct_data={"cid": credentials["_id"], "status": resp.status}
				)
				return

			# Set admin role if Grafana admin resource is present
			if self.RBACService.has_resource_access(authz, "*", [_GRAFANA_ADMIN_RESOURCE]):
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
							struct_data={"cid": credentials["_id"], "status": resp.status}
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
							struct_data={"cid": credentials["_id"], "status": resp.status}
						)
