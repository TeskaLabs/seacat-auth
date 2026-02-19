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
from .view.abc import RoleView
from .view.propagated_role import global_role_id_to_propagated
from ...generic import amerge_sorted, ReverseSortingString


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


	def _prepare_views(
		self,
		tenant_id: str | None,
		exclude_global: bool = False,
		exclude_propagated: bool = False
	) -> typing.List[RoleView]:
		assert tenant_id != "*"
		views = []
		if tenant_id:
			views.append(CustomTenantRoleView(self.StorageService, self.RoleCollection, tenant_id))
			if not exclude_propagated:
				views.append(PropagatedRoleView(self.StorageService, self.RoleCollection, tenant_id))
		if not exclude_global:
			views.append(GlobalRoleView(self.StorageService, self.RoleCollection))
		return views


	async def _get_tenants_where_roles_assignable(self, target_cid: str) -> typing.Set[str]:
		"""
		Returns a set of tenants where the caller can assign roles to the target credentials.

		Args:
			target_cid: Credentials ID of the target user.

		Returns:
			Set of tenant IDs where the caller can assign roles to the target user.
			Includes None if the caller can assign global roles.
		"""
		target_tenants = set(await self.TenantService.get_tenants(target_cid))

		authz = asab.contextvars.Authz.get()
		if authz.has_superuser_access():
			# Superusers can assign roles in any tenant plus global roles
			return {None, *target_tenants}

		tenant = asab.contextvars.Tenant.get()
		if tenant not in target_tenants:
			# Target does not have access to the current tenant, so no editable tenants
			return set()

		# Current tenant is editable if the user has ROLE_ASSIGN in it
		if authz.has_resource_access(ResourceId.ROLE_ASSIGN):
			return {tenant}
		else:
			return set()


	async def list_roles(
		self,
		tenant_id: str | None = None,
		page: int = 0,
		limit: int | None = None,
		sort: list[tuple[str, int]] | None = None,
		name_filter: str | None = None,
		description_filter: str | None = None,
		resource_filter: str | None = None,
		exclude_global: bool = False,
		exclude_propagated: bool = False,
		assign_cid: str | None = None,
		assigned_filter: bool | None = None,
		assignable_filter: bool | None = None,
	):
		"""
		List roles matching the given criteria.

		Args:
			tenant_id:
				If given, list roles defined in the given tenant plus global roles.
				If None or "*", list global roles only.
			page: Page number (0..N).
			limit: Page size. If None, return all matching roles.
			sort: List of (field, direction) tuples to sort the results by.
				Direction is 1 for ascending and -1 for descending.
				Supported fields are "_id", "description", "assignment.assigned" and "assignment.editable".
			name_filter: If given, return only roles whose ID contains this substring.
			description_filter: If given, return only roles whose description contains this substring.
			resource_filter: If given, return only roles with the given resource.
			exclude_global: If True, exclude global roles from the results.
			exclude_propagated: If True, exclude propagated global roles from the results.
			assign_cid:
				If given, add a boolean field "assigned" indicating whether the role is assigned to the given
				credentials ID. Also filter the results by the `assigned_filter` parameter if given.
				Requires that the caller has ROLE_ASSIGN in the target tenant (if `tenant_id` is given).
			assigned_filter:
				If given, filter results by the value of the "assigned" field.
				Requires `assign_cid` to be set.
			assignable_filter:
				If given, add a boolean field "assignable" indicating whether the role can be assigned to the
				credentials ID by the caller. Also filter the results by this field if given.
				Requires `assign_cid` to be set. To be assignable, the caller must have ROLE_ASSIGN in the target
				tenant (if `tenant_id` is given) and the target credentials must have access to the target tenant
				(if `tenant_id` is given).
		"""
		authz = asab.contextvars.Authz.get()
		if tenant_id in {"*", None}:
			tenant_id = None
		else:
			authz.require_tenant_access()

		if assign_cid is not None:
			cred_roles = list(await self.get_roles_by_credentials(
				assign_cid, [tenant_id] if tenant_id is not None else None)) or []
			editable_tenants = list(await self._get_tenants_where_roles_assignable(target_cid=assign_cid)) or []
		else:
			editable_tenants = None
			cred_roles = None

		views = self._prepare_views(tenant_id, exclude_global, exclude_propagated)
		counts = [
			await view.count(
				id_substring=name_filter,
				description_substring=description_filter,
				resource_filter=resource_filter,
				flag_tenants=editable_tenants,
				tenant_flag_filter=assignable_filter,
				flag_ids=cred_roles,
				id_flag_filter=assigned_filter,
			)
			for view in views
		]

		offset = (page or 0) * (limit or 0)
		iterators = []
		for count, view in zip(counts, views):
			if count == 0:
				# Skip empty views to optimize iteration
				continue

			iterators.append(view.iterate(
				sort=sort,
				id_substring=name_filter,
				description_substring=description_filter,
				resource_filter=resource_filter,
				flag_tenants=editable_tenants,
				tenant_flag_filter=assignable_filter,
				flag_ids=cred_roles,
				id_flag_filter=assigned_filter,
				set_fields={"assignment": {
					"assigned": "$_id_flag",
					"editable": "$_tenant_flag",
				}}
			))

		roles = []
		async for role in amerge_sorted(
			*iterators,
			key=lambda r: _sorting_key(r, sort),
			offset=offset,
			limit=limit,
		):
			roles.append(role)

		result = {
			"count": sum(counts),
			"data": roles,
		}

		return result


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
			authz.require_tenant_access(tenant_id)
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

		_assert_role_is_editable(role_current)

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

		_assert_role_is_editable(role_current)

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
	) -> typing.List[str]:
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


	async def iterate_role_assignments(
		self,
		role_id: str | typing.Iterable,
		page: int = 0,
		limit: int | None = None,
	) -> typing.AsyncIterator[dict]:
		"""
		Iterate all credentials IDs that are assigned a specified role

		Args:
			role_id:
				Role ID (or a list) to filter by
			page:
				Page number (0..N)
			limit:
				Page size. If None, return all matching assignments.
		Yields:
			Credentials IDs assigned the role
		"""
		query_filter = {"r": role_id}
		collection = self.StorageService.Database[self.CredentialsRolesCollection]
		cursor = collection.find(query_filter)
		cursor.sort("_id", 1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)
		async for assignment in cursor:
			yield assignment


	async def count_role_assignments(self, role_id: str | typing.Iterable) -> int:
		"""
		Count all credentials IDs that are assigned a specified role

		Args:
			role_id:
				Role ID (or a list) to filter by
		Yields:
			Credentials IDs assigned the role
		"""
		query_filter = {"r": role_id}
		collection = self.StorageService.Database[self.CredentialsRolesCollection]
		return await collection.count_documents(query_filter)


	async def list_role_credentials(
		self,
		role_id: str | typing.Iterable,
		page: int = 0,
		limit: int = None,
		ids_only: bool = False,
	) -> dict:
		"""
		List specific role's assigned credentials

		Args:
			role_id:
				Role ID or list of role IDs to filter by
			page:
				Page number (0..N)
			limit:
				Page size. If None, return all matching assignments.
			ids_only:
				Summarize the assignments into an array of credential IDs only
		Returns:
			dict: A dict with "data" and "count" keys.
				"data" is a list of credentials objects or, if ids_only is True, a list of credential IDs only.
				"count" is the total number of assignments.
		"""
		assignments = []
		async for assignment in self.iterate_role_assignments(role_id, page, limit):
			assignments.append(assignment)

		if ids_only is True:
			data = [assignment["c"] for assignment in assignments]
		else:
			data = []
			for assignment in assignments:
				credentials = await self.CredentialService.get(assignment["c"])
				credentials["assignment"] = assignment
				data.append(credentials)

		return {
			"data": data,
			"count": await self.count_role_assignments(role_id)
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


def _assert_role_is_editable(role: dict):
	if role.get("read_only"):
		L.log(asab.LOG_NOTICE, "Role is not editable.", struct_data={"role_id": role["_id"]})
		raise exceptions.NotEditableError("Role is not editable.")
	return True


def _sorting_key(
	role: dict,
	sort: list[tuple[str, int]],
):
	keys = []
	if sort:
		for field, direction in sort:
			if field in {"_id", "description"}:
				if direction == 1:
					keys.append(role.get(field, ""))
				elif direction == -1:
					keys.append(ReverseSortingString(role.get(field, "")))
			elif field in {"assignment.assigned", "assignment.editable"}:
				keys.append(direction * role.get("assignment", {}).get(field.split(".")[1], False))

	return keys
