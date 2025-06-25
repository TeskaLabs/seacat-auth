import logging
import re
import typing
import asab.contextvars
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.storage.exceptions
import asab.exceptions

from ... import exceptions
from ...api import local_authz
from ...models.const import ResourceId
from ...events import EventTypes
from .view import GlobalRoleView, PropagatedRoleView, CustomTenantRoleView
from .view.propagated_role import global_role_id_to_propagated


L = logging.getLogger(__name__)


SUPERUSER_ROLE_ID = "*/superuser"
SUPERUSER_ROLE_PROPERTIES = {
	"label": "Superuser",
	"description": "Has superuser access. Passes any access control check, including the access to any tenant.",
	"resources": [ResourceId.SUPERUSER],
}

TENANT_ADMIN_ROLE_PROPERTIES = {
	"label": "Authorization admin",
	"description":
		"Manages access control. Creates and modifies tenant roles, invites new tenant members and "
		"assigns roles to them.",
	"resources": [
		ResourceId.TENANT_ACCESS,
		ResourceId.TENANT_EDIT,
		ResourceId.TENANT_ASSIGN,
		ResourceId.TENANT_DELETE,
		ResourceId.ROLE_ACCESS,
		ResourceId.ROLE_EDIT,
		ResourceId.TENANT_ACCESS,
		ResourceId.ROLE_ASSIGN,
	],
	"propagated": True,
}


class RoleService(asab.Service):
	"""
	Role object schema:
	{
		"_id": str,
		"description": str,
		"resources": [str, str, ...],
		"managed_by": str,
	}
	"""

	RoleCollection = "r"
	CredentialsRolesCollection = "cr"
	RoleNamePattern = r"[a-zA-Z_][a-zA-Z0-9_-]{0,31}"


	def __init__(self, app, service_name="seacatauth.RoleService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.CredentialService = app.get_service("seacatauth.CredentialsService")
		self.ResourceService = app.get_service("seacatauth.ResourceService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.RBACService = self.App.get_service("seacatauth.RBACService")
		# The format is always {tenant or "*"}/{role_name}!
		# Tenant name is always validated by tenant service
		self.RoleIdRegex = re.compile(r"^([^/]+)/({role})$".format(
			role=self.RoleNamePattern
		))
		self.RoleNameRegex = re.compile(self.RoleNamePattern)

		# Role assigned to any user upon tenant assignment
		# Must be a global role with propagation enabled
		self.TenantBaseRole = asab.Config.get(
			"seacatauth:tenant", "base_role", fallback="") or None

		# Role assigned to the tenant creator upon new tenant creation
		# Must be a global role with propagation enabled
		self.TenantAdminRole = asab.Config.get(
			"seacatauth:tenant", "admin_role", fallback="") or None


	async def initialize(self, app):
		with local_authz(self.Name, resources={ResourceId.SUPERUSER}):
			await self._ensure_system_roles()


	async def _ensure_preset_role(self, role_id: str, properties: dict, update: bool = True):
		try:
			existing_role = await self.get(role_id)
		except KeyError:
			# Create the role
			upsertor = self.StorageService.upsertor(self.RoleCollection, role_id)
			for k, v in properties.items():
				upsertor.set(k, v)
			await upsertor.execute()
			L.log(asab.LOG_NOTICE, "Role created.", struct_data={"role_id": role_id})
			return

		if not update:
			return

		# Role exists - check its attributes
		for k, v in properties.items():
			if existing_role.get(k) != v:
				break
		else:
			# All values are up-to-date
			return

		# Update the role
		upsertor = self.StorageService.upsertor(
			self.RoleCollection,
			role_id,
			version=existing_role["_v"]
		)
		for k, v in properties.items():
			upsertor.set(k, v)
		await upsertor.execute()
		L.log(asab.LOG_NOTICE, "Role updated.", struct_data={"role_id": role_id})


	async def _ensure_system_roles(self):
		"""
		Check if all Seacat Auth system roles exist. Create them if they don't.
		Update them if outdated.
		"""
		await self._ensure_preset_role(SUPERUSER_ROLE_ID, SUPERUSER_ROLE_PROPERTIES)

		if self.TenantBaseRole:
			if not await self._ensure_propagated_role(self.TenantBaseRole):
				L.warning("Tenant base role is not ready.", struct_data={"role": self.TenantBaseRole})

		if self.TenantAdminRole:
			await self._ensure_preset_role(self.TenantAdminRole, TENANT_ADMIN_ROLE_PROPERTIES, update=False)
			if not await self._ensure_propagated_role(self.TenantAdminRole):
				L.warning("Tenant admin role is not ready.", struct_data={"role": self.TenantAdminRole})


	def _prepare_views(self, tenant_id: str | None, exclude_global: bool = False, exclude_propagated: bool = False):
		assert tenant_id != "*"
		views = []
		if tenant_id:
			views.append(CustomTenantRoleView(self.StorageService, self.RoleCollection, tenant_id))
			if not exclude_propagated:
				views.append(PropagatedRoleView(self.StorageService, self.RoleCollection, tenant_id))
		if not exclude_global:
			views.append(GlobalRoleView(self.StorageService, self.RoleCollection))
		return views


	def _role_tenant_id(self, role_id: str):
		tenant_id = role_id.split("/")[0]
		if tenant_id == "*":
			return None
		else:
			return tenant_id


	async def list_roles(
		self,
		tenant_id: typing.Optional[str] = None,
		page: int = 0,
		limit: int = None,
		name_filter: str = None,
		resource_filter: str = None,
		exclude_global: bool = False,
		exclude_propagated: bool = False,
		assign_cid: typing.Optional[str] = None,
	):
		authz = asab.contextvars.Authz.get()
		if tenant_id in {"*", None}:
			tenant_id = None
		else:
			authz.require_tenant_access()

		if assign_cid is not None:
			cred_roles = set(await self.get_roles_by_credentials(
				assign_cid, [tenant_id] if tenant_id is not None else None))
		else:
			cred_roles = None

		views = self._prepare_views(tenant_id, exclude_global, exclude_propagated)
		counts = [
			await view.count(name_filter, resource_filter)
			for view in views
		]
		roles = []
		offset = (page or 0) * (limit or 0)
		for count, view in zip(counts, views):
			if offset > count:
				offset -= count
				continue

			async for role in view.iterate(
				offset=offset,
				limit=(limit - len(roles)) if limit else None,
				sort=("_id", 1),
				name_filter=name_filter,
				resource_filter=resource_filter,
			):
				if cred_roles is not None:
					role["assign_cid"] = {
						"assigned": role["_id"] in cred_roles,
						"editable": await self.can_assign_role(role["_id"], target_cid=assign_cid),
					}
				roles.append(role)

			if limit and len(roles) >= limit:
				break

			offset = 0

		result = {
			"count": sum(counts),
			"data": roles,
		}
		if assign_cid is not None:
			result["assign_cid"] = assign_cid

		return result


	async def can_assign_role(self, role_id: str, target_cid: str) -> bool:
		authz = asab.contextvars.Authz.get()
		tenant_id, _ = self.parse_role_id(role_id)

		if tenant_id is not None and not (await self.TenantService.has_tenant_assigned(target_cid, tenant_id)):
			return False

		# Superusers can assign any role, including global roles
		if authz.has_superuser_access():
			return True

		if tenant_id is None:
			# Global roles can be assigned by superusers only
			return False

		# Tenant roles can be assigned only if their tenant is in the current authorization context
		if not tenant_id == asab.contextvars.Tenant.get():
			return False
		if not authz.has_tenant_access():
			return False
		return True



	async def _get(self, role_id: str):
		tenant_id, role_name = self.parse_role_id(role_id)
		try:
			if not tenant_id:
				return await GlobalRoleView(self.StorageService, self.RoleCollection).get(role_id)
			elif role_name.startswith("~"):
				return await PropagatedRoleView(self.StorageService, self.RoleCollection, tenant_id).get(role_id)
			else:
				return await CustomTenantRoleView(self.StorageService, self.RoleCollection, tenant_id).get(role_id)
		except KeyError:
			raise exceptions.RoleNotFoundError(role_id)


	async def get(self, role_id: str):
		tenant_id, _ = self.parse_role_id(role_id)
		authz = asab.contextvars.Authz.get()
		if tenant_id:
			authz.require_tenant_access()
		return await self._get(role_id)


	async def get_role_resources(self, role_id: str):
		role_obj = await self._get(role_id)
		return role_obj["resources"]


	async def create(
		self,
		role_id: str,
		label: str = None,
		description: str = None,
		resources: typing.Optional[typing.Iterable] = None,
		propagated: bool = False,
		from_role: typing.Optional[str] = None,
		_managed_by_seacat_auth: bool = False,
	):
		authz = asab.contextvars.Authz.get()
		tenant_id, role_name = self.parse_role_id(role_id)
		self.validate_role_name(role_name)
		if tenant_id:
			authz.require_tenant_access()
		else:
			# Only superusers can create global roles
			authz.require_superuser_access()

		# Check existence before creating to prevent shadowing shared roles with tenant roles
		try:
			await self._get(role_id)
			raise asab.exceptions.Conflict(key="_id", value=role_id)
		except exceptions.RoleNotFoundError:
			pass

		if from_role:
			# Use specified role as a template
			source_role = await self.get(from_role)
			if not description:
				description = source_role.get("description")
			if not resources:
				if tenant_id is not None or propagated is True:
					# Tenant and propagated roles cannot access global-only resources
					resources = [
						resource_id for resource_id in source_role.get("resources")
						if not await self.ResourceService.is_global_only_resource(resource_id)
					]
				else:
					resources = source_role.get("resources")

		upsertor = self.StorageService.upsertor(
			self.RoleCollection,
			role_id
		)
		if tenant_id:
			upsertor.set("tenant", tenant_id)
		if resources:
			await self._validate_role_resources(role_id, propagated, resources)
			upsertor.set("resources", resources)
		else:
			upsertor.set("resources", [])
		if label:
			upsertor.set("label", label)
		if description:
			upsertor.set("description", description)
		if propagated:
			upsertor.set("propagated", True)
		if _managed_by_seacat_auth:
			upsertor.set("managed_by", "seacat-auth")

		role_id = await upsertor.execute(event_type=EventTypes.ROLE_CREATED)
		L.log(asab.LOG_NOTICE, "Role created", struct_data={"role_id": role_id})

		self.App.PubSub.publish("Role.created!", role_id=role_id, asynchronously=True)

		return role_id


	def parse_role_id(self, role_id: str) -> (typing.Optional[str], str):
		tenant_id, role_name = role_id.split("/", 1)
		if tenant_id == "*":
			tenant_id = None
		return tenant_id, role_name


	def validate_role_name(self, role_name: str):
		match = self.RoleNameRegex.match(role_name)
		if match is None:
			raise asab.exceptions.ValidationError(
				"Role ID must match the format {tenant_name}/{role_name}, "
				"where {tenant_name} is either '*' or the name of an existing tenant "
				"and {role_name} consists only of characters 'a-z0-9_-', "
				"starts with a letter or underscore, and is between 1 and 32 characters long."
			)


	async def delete(self, role_id: str):
		"""
		Delete a role. Also remove all role assignments.
		"""
		# Verify that role exists and validate access
		try:
			role_current = await self.get(role_id)
		except exceptions.RoleNotFoundError as e:
			L.log(asab.LOG_NOTICE, "Role not found.", struct_data={"role_id": role_id})
			raise e

		assert_role_is_editable(role_current)

		# Unassign the role from all credentials
		await self.delete_role_assignments(role_current)

		# Delete the role
		await self.StorageService.delete(self.RoleCollection, role_id)
		L.log(asab.LOG_NOTICE, "Role deleted", struct_data={"role_id": role_id})
		self.App.PubSub.publish("Role.deleted!", role_id=role_id, asynchronously=True)
		return "OK"


	async def update(
		self, role_id: str, *,
		label: str = None,
		description: str = None,
		resources_to_set: list = None,
		resources_to_add: list = None,
		resources_to_remove: list = None,
	):
		"""
		Verify authorization and integrity and update role.
		"""
		# Verify that role exists and validate access
		try:
			role_current = await self.get(role_id)
		except exceptions.RoleNotFoundError as e:
			L.log(asab.LOG_NOTICE, "Role not found.", struct_data={"role_id": role_id})
			raise e

		assert_role_is_editable(role_current)

		# Validate resources
		resources_to_assign = set().union(
			resources_to_set or [],
			resources_to_add or [],
		)
		await self._validate_role_resources(role_id, role_current.get("propagated"), resources_to_assign)

		if resources_to_set is None:
			resources_to_set = set(role_current["resources"])
		else:
			resources_to_set = set(resources_to_set)
			for res_id in resources_to_set:
				try:
					resource = await self.ResourceService.get(res_id)
				except KeyError:
					raise KeyError(res_id)
				if resource.get("deleted") is True:
					raise KeyError(res_id)
		if resources_to_add is not None:
			for res_id in resources_to_add:
				try:
					await self.ResourceService.get(res_id)
				except KeyError:
					raise KeyError(res_id)
				resources_to_set.add(res_id)
		if resources_to_remove is not None:
			for res_id in resources_to_remove:
				# Do not check if resource exists to allow deleting leftovers
				resources_to_set.remove(res_id)

		upsertor = self.StorageService.upsertor(
			self.RoleCollection,
			role_id,
			version=role_current["_v"]
		)

		if resources_to_set != set(role_current["resources"]):
			upsertor.set("resources", list(resources_to_set))

		if label is not None:
			upsertor.set("label", label)
		if description is not None:
			upsertor.set("description", description)

		await upsertor.execute(event_type=EventTypes.ROLE_UPDATED)
		L.log(asab.LOG_NOTICE, "Role updated", struct_data={"role_id": role_id})
		self.App.PubSub.publish("Role.updated!", role_id=role_id, asynchronously=True)


	async def _validate_role_resources(self, role_id: str, propagated: bool, resources: typing.Iterable):
		"""
		Check if resources exist and can be assigned to role
		"""
		tenant_id, _ = self.parse_role_id(role_id)
		for resource_id in resources:
			# Verify that resource exists
			await self.ResourceService.get(resource_id)

			if (
				(tenant_id is not None or propagated is True)
				and await self.ResourceService.is_global_only_resource(resource_id)
			):
				# Global-only resources cannot be assigned to tenant roles or globally defined tenant roles
				message = "Cannot assign global-only resources to tenant roles or to propagated global roles."
				L.error(message, struct_data={"resource_id": resource_id, "role_id": role_id})
				raise asab.exceptions.ValidationError(message)


	async def get_roles_by_credentials(
		self,
		credentials_id: str,
		tenants: list = None,
		limit: typing.Optional[int] = None,
		page: int = 0
	):
		"""
		Returns a list of roles assigned to the given `credentials_id`.
		Includes roles that match the given `tenant` plus global roles.
		"""
		collection = await self.StorageService.collection(self.CredentialsRolesCollection)
		query_filter = {
			"c": credentials_id,
			"t": {"$in": [None, *(tenants or [])]}
		}
		cursor = collection.find(query_filter)
		cursor.sort("r", 1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		result = []
		async for assignment in cursor:
			result.append(assignment["r"])
		return result


	async def set_roles(self, credentials_id: str, roles: list, tenant: str = "*", include_global: bool = False):
		"""
		Assign a list of roles to given credentials and unassign all their current roles that are not listed
		"""
		# Sort the requested roles
		requested_tenant_roles = set()
		requested_global_roles = set()
		for role in roles:
			t, _ = role.split("/", 1)
			if t == "*":
				requested_global_roles.add(role)
			elif t == tenant:
				requested_tenant_roles.add(role)
			else:
				raise KeyError("Role {} not found in tenant {}.".format(role, tenant))

		if len(requested_tenant_roles) > 0:
			# Verify the target's tenant access
			if not await self.TenantService.has_tenant_assigned(credentials_id, tenant):
				raise asab.exceptions.ValidationError(
					"Credentials {!r} do not have access to tenant {!r}.".format(credentials_id, tenant))

		# Sort the credentials' currently assigned roles
		current_tenant_roles = set()
		current_global_roles = set()
		for role in await self.get_roles_by_credentials(credentials_id, [tenant]):
			t, _ = role.split("/", 1)
			if t == "*":
				current_global_roles.add(role)
			else:
				current_tenant_roles.add(role)

		# Compute the difference between the current and the desired state
		# Determine which roles need to be un/assigned
		roles_to_assign = requested_tenant_roles - current_tenant_roles
		roles_to_unassign = current_tenant_roles - requested_tenant_roles
		if include_global:
			roles_to_assign.update(requested_global_roles - current_global_roles)
			roles_to_unassign.update(current_global_roles - requested_global_roles)

		# Check that credentials exist
		# (Nonexistent credentials can be only unassigned)
		if len(roles_to_assign) > 0:
			await self.CredentialService.detail(credentials_id)

		# Assign roles
		for role in roles_to_assign:
			await self.assign_role(credentials_id, role, verify_tenant=False, verify_credentials=False)

		# Unassign roles
		for role in roles_to_unassign:
			await self.unassign_role(credentials_id, role)


	async def list_role_assignments(self, role_id: str | typing.Iterable, page: int = 0, limit: int = None):
		"""
		List all role assignments of a specified role
		"""
		if isinstance(role_id, str):
			query_filter = {"r": role_id}
		else:
			query_filter = {"r": {"$in": role_id}}

		collection = self.StorageService.Database[self.CredentialsRolesCollection]
		cursor = collection.find(query_filter)

		cursor.sort("_c", -1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		assignments = []
		async for assignment in cursor:
			assignments.append(assignment)

		return {
			"data": assignments,
			"count": await collection.count_documents(query_filter)
		}


	async def assign_role(
		self, credentials_id: str, role_id: str,
		verify_role: bool = True,
		verify_tenant: bool = True,
		verify_credentials: bool = True,
		verify_credentials_has_tenant: bool = True
	):
		"""
		Check all integrity prerequisites and assign role to credentials
		"""
		authz = asab.contextvars.Authz.get()
		tenant_id, _ = self.parse_role_id(role_id)
		if tenant_id:
			authz.require_resource_access(ResourceId.ROLE_ASSIGN)
		else:
			authz.require_superuser_access()

		if verify_role:
			try:
				await self.get(role_id)
			except KeyError:
				raise exceptions.RoleNotFoundError(role_id)

		if verify_tenant and tenant_id is not None:
			await self.TenantService.get_tenant(tenant_id)

		if verify_credentials:
			try:
				await self.CredentialService.detail(credentials_id)
			except KeyError:
				raise exceptions.CredentialsNotFoundError(credentials_id)

		if verify_credentials_has_tenant and tenant_id is not None:
			# NOTE: This check does not take into account tenant access granted via global resources
			# such as "authz:superuser" or "authz:tenant:access", which is correct.
			# To get a tenant role assigned, the user needs to have the tenant explicitly assigned.
			if not await self.TenantService.has_tenant_assigned(credentials_id, tenant_id):
				raise exceptions.TenantNotAssignedError(credentials_id, tenant_id)

		await self._do_assign_role(credentials_id, role_id, tenant_id)


	async def _do_assign_role(self, credentials_id: str, role_id: str, tenant: str):
		"""
		Assign role to credentials
		"""
		assignment_id = "{} {}".format(credentials_id, role_id)

		upsertor = self.StorageService.upsertor(self.CredentialsRolesCollection, obj_id=assignment_id)
		upsertor.set("c", credentials_id)
		upsertor.set("r", role_id)
		if tenant != "*":
			upsertor.set("t", tenant)

		try:
			await upsertor.execute(event_type=EventTypes.ROLE_ASSIGNED)
		except asab.storage.exceptions.DuplicateError as e:
			if hasattr(e, "KeyValue") and e.KeyValue is not None:
				key, value = e.KeyValue.popitem()
				raise asab.exceptions.Conflict("Role already assigned.", key=key, value=value) from e
			else:
				raise asab.exceptions.Conflict("Role already assigned.") from e

		self.App.PubSub.publish("Role.assigned!", credentials_id=credentials_id, role_id=role_id, asynchronously=True)
		L.log(asab.LOG_NOTICE, "Role assigned", struct_data={
			"cid": credentials_id,
			"role": role_id,
		})


	async def unassign_role(self, credentials_id: str, role_id: str):
		"""
		Remove role from credentials
		"""
		authz = asab.contextvars.Authz.get()
		tenant_id, _ = self.parse_role_id(role_id)
		if tenant_id:
			authz.require_resource_access(ResourceId.ROLE_ASSIGN)
		else:
			authz.require_superuser_access()

		assignment_id = "{} {}".format(credentials_id, role_id)
		await self.StorageService.delete(self.CredentialsRolesCollection, assignment_id)
		self.App.PubSub.publish("Role.unassigned!", credentials_id=credentials_id, role_id=role_id, asynchronously=True)
		L.log(asab.LOG_NOTICE, "Role unassigned", struct_data={
			"cid": credentials_id,
			"role": role_id,
		})


	async def delete_role_assignments(self, role: dict):
		"""
		Delete all role assignments of a specified role
		"""
		authz = asab.contextvars.Authz.get()

		role_id = role["_id"]
		tenant_id, role_name = self.parse_role_id(role_id)
		if tenant_id:
			authz.require_resource_access(ResourceId.ROLE_ASSIGN)
		else:
			authz.require_superuser_access()

		collection = await self.StorageService.collection(self.CredentialsRolesCollection)
		result = await collection.delete_many({"r": role_id})
		deleted_count = result.deleted_count

		# For propagated global roles delete also their assignments within tenants
		if tenant_id is None and role.get("propagated") is True:
			result = await collection.delete_many({"r": re.compile(r"^.+/~{}$".format(re.escape(role_name)))})
			deleted_count += result.deleted_count

		L.log(asab.LOG_NOTICE, "Role unassigned.", struct_data={
			"role_id": role_id,
			"deleted_count": deleted_count,
		})


	async def get_assigned_role(self, credentials_id: str, role_id: str):
		assignment_id = "{} {}".format(credentials_id, role_id)
		return await self.StorageService.get(self.CredentialsRolesCollection, assignment_id)


	async def _ensure_propagated_role(self, role_id: str) -> bool:
		if not role_id.startswith("*/"):
			L.error("Role name must start with '*/'.", struct_data={"role": role_id})
			return False

		try:
			role = await self.get(role_id)
		except exceptions.RoleNotFoundError:
			L.warning("Role not found.", struct_data={"role": role_id})
			return False

		if not role.get("propagated"):
			L.warning("Role is not propagated.", struct_data={"role": role_id})
			return False

		return True


	async def assign_tenant_base_role(self, credentials_id: str, tenant_id: str):
		if not self.TenantBaseRole:
			raise exceptions.RoleNotFoundError(self.TenantBaseRole)
		await self.assign_role(
			credentials_id,
			global_role_id_to_propagated(self.TenantBaseRole, tenant_id),
		)


	async def assign_tenant_admin_role(self, credentials_id: str, tenant_id: str):
		if not self.TenantAdminRole:
			raise exceptions.RoleNotFoundError(self.TenantBaseRole)
		await self.assign_role(
			credentials_id,
			global_role_id_to_propagated(self.TenantAdminRole, tenant_id),
		)


def assert_role_is_editable(role: dict):
	if role.get("read_only"):
		L.log(asab.LOG_NOTICE, "Role is not editable.", struct_data={"role_id": role["_id"]})
		raise exceptions.NotEditableError("Role is not editable.")
	return True
