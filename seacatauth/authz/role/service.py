import logging
import re
from typing import Optional

import asab.storage.exceptions
import asab.exceptions
from ... import exceptions

from ...events import EventTypes

#

L = logging.getLogger(__name__)


#


class RoleService(asab.Service):
	"""
	Role object schema:
	{
		"_id": str,
		"resources": [str, str, ...]
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


	async def list(
		self, tenant: Optional[str] = None, page: int = 0, limit: int = None, *,
		resource: str = None,
		active_only: bool = False,
	):
		collection = self.StorageService.Database[self.RoleCollection]
		query_filter = {}
		if tenant is not None:
			query_filter["tenant"] = {"$in": [tenant, None]}
		if resource is not None:
			query_filter["resources"] = resource
		if active_only is True:
			query_filter["deleted"] = {"$in": [False, None]}

		cursor = collection.find(query_filter)

		cursor.sort("_c", -1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		roles = []
		count = await collection.count_documents(query_filter)
		async for role_dict in cursor:
			roles.append(role_dict)

		return {
			"result": "OK",
			"count": count,
			"data": roles,
		}


	async def get(self, role_id: str):
		try:
			result = await self.StorageService.get(self.RoleCollection, role_id)
		except KeyError:
			raise exceptions.RoleNotFoundError(role_id)
		return result


	async def get_role_resources(self, role_id: str):
		role_obj = await self.get(role_id)
		return role_obj["resources"]


	async def create(self, role_id: str):
		# TODO: No return dicts! This should return role_id or raise (custom) error.
		match = self.RoleIdRegex.match(role_id)
		if match is None:
			return {
				"result": "INVALID-VALUE",
				"message":
					"Role ID must match the format {tenant_name}/{role_name}, "
					"where {tenant_name} is either '*' or the name of an existing tenant "
					"and {role_name} consists only of characters 'a-z0-9_-', "
					"starts with a letter or underscore, and is between 1 and 32 characters long.",
			}
		try:
			tenant = await self.get_role_tenant(role_id)
		except KeyError:
			tenant, _ = role_id.split("/", 1)
			raise KeyError("Tenant '{}' not found.".format(tenant))

		upsertor = self.StorageService.upsertor(
			self.RoleCollection,
			role_id
		)
		upsertor.set("resources", [])
		if tenant != "*":
			upsertor.set("tenant", tenant)
		try:
			await upsertor.execute(event_type=EventTypes.ROLE_CREATED)
			L.log(asab.LOG_NOTICE, "Role created", struct_data={"role_id": role_id})
		except asab.storage.exceptions.DuplicateError:
			L.error("Couldn't create role: Already exists", struct_data={"role_id": role_id})
			return {
				"result": "CONFLICT",
				"message": "Role '{}' already exists.".format(role_id)
			}
		return "OK"


	async def delete(self, role_id: str):
		"""
		Delete a role. Also remove all role assignments.
		"""
		# Unassign the role from all credentials
		await self.delete_role_assignments(role_id)

		# Delete the role
		await self.StorageService.delete(self.RoleCollection, role_id)
		L.log(asab.LOG_NOTICE, "Role deleted", struct_data={'role_id': role_id})
		return "OK"


	async def update(
		self, role_id: str, *,
		description: str = None,
		resources_to_set: list = None,
		resources_to_add: list = None,
		resources_to_remove: list = None
	):
		# Verify that role exists
		role_current = await self.get(role_id)

		# Verify that role tenant exists
		try:
			tenant = await self.get_role_tenant(role_id)
		except KeyError as e:
			raise KeyError("Tenant of role {!r} not found. Please delete this role.".format(role_id)) from e

		# Validate resources
		resources_to_assign = set().union(
			resources_to_set or [],
			resources_to_add or [],
			resources_to_remove or []
		)
		if tenant != "*":
			# TENANT role
			# Global-only resources cannot be assigned to a tenant role
			for resource in resources_to_assign:
				if self.ResourceService.is_global_only_resource(resource):
					message = "Cannot assign global-only resources to tenant roles"
					L.warning(message, struct_data={"resource": resource, "role": role_id})
					raise asab.exceptions.ValidationError(message)

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

		log_data = {"role": role_id}

		if resources_to_set != set(role_current["resources"]):
			upsertor.set("resources", list(resources_to_set))
			log_data["resources"] = ", ".join(resources_to_set)

		if description is not None:
			upsertor.set("description", description)
			log_data["description"] = description

		await upsertor.execute(event_type=EventTypes.ROLE_UPDATED)
		L.log(asab.LOG_NOTICE, "Role updated", struct_data=log_data)
		return "OK"


	async def get_roles_by_credentials(self, credentials_id: str, tenants: list = None):
		"""
		Returns a list of roles assigned to the given `credentials_id`.
		Includes roles that match the given `tenant` plus global roles.
		"""
		result = []
		coll = await self.StorageService.collection(self.CredentialsRolesCollection)
		async for obj in coll.find({
			'c': credentials_id,
			't': {"$in": [None, *(tenants or [])]}
		}):
			result.append(obj["r"])
		return result


	async def set_roles(self, credentials_id: str, roles: list, tenant: str = "*", include_global: bool = False):
		"""
		Assign a list of roles to given credentials and unassign all their current roles that are not listed
		"""
		# Determine whether tenant roles can be assigned
		has_tenant_assigned = await self.TenantService.has_tenant_assigned(credentials_id, tenant)

		# Sort the requested roles
		requested_tenant_roles = set()
		requested_global_roles = set()
		for role in roles:
			t, _ = role.split("/", 1)
			if t == "*":
				requested_global_roles.add(role)
			elif t == tenant:
				if not has_tenant_assigned:
					raise asab.exceptions.ValidationError(
						"Cannot assign role {!r}: Credentials {!r} does not have access to tenant {!r}.".format(
							role, credentials_id, tenant))
				requested_tenant_roles.add(role)
			else:
				raise KeyError("Role {} not found in tenant {}.".format(role, tenant))

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


	async def list_role_assignments(self, role_id, page: int = 0, limit: int = None):
		"""
		List all role assignments of a specified role
		"""
		collection = self.StorageService.Database[self.CredentialsRolesCollection]
		query_filter = {"r": role_id}
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
		if verify_role:
			try:
				await self.get(role_id)
			except KeyError:
				raise exceptions.RoleNotFoundError(role_id)

		tenant, _ = role_id.split("/", 1)
		if verify_tenant and tenant != "*":
			try:
				tenant = await self.TenantService.get_tenant(role_id)
			except KeyError:
				raise exceptions.TenantNotFoundError(tenant)

		if verify_credentials:
			try:
				await self.CredentialService.detail(credentials_id)
			except KeyError:
				raise exceptions.CredentialsNotFoundError(credentials_id)

		if verify_credentials_has_tenant and tenant != "*":
			# NOTE: This check does not take into account tenant access granted via global resources
			# such as "authz:superuser" or "authz:tenant:access", which is correct.
			# To get a tenant role assigned, the user needs to have the tenant explicitly assigned.
			if not await self.TenantService.has_tenant_assigned(credentials_id, tenant):
				raise exceptions.TenantNotAuthorizedError(credentials_id, tenant)

		await self._do_assign_role(credentials_id, role_id, tenant)


	async def _do_assign_role(self, credentials_id: str, role_id: str, tenant: str):
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

		L.log(asab.LOG_NOTICE, "Role assigned", struct_data={
			"cid": credentials_id,
			"role": role_id,
		})


	async def unassign_role(self, credentials_id: str, role_id: str):
		assignment_id = "{} {}".format(credentials_id, role_id)
		await self.StorageService.delete(self.CredentialsRolesCollection, assignment_id)
		L.log(asab.LOG_NOTICE, "Role unassigned", struct_data={
			"cid": credentials_id,
			"role": role_id,
		})


	async def delete_role_assignments(self, role_id):
		"""
		Delete all role assignments of a specified role
		"""
		collection = await self.StorageService.collection(self.CredentialsRolesCollection)

		result = await collection.delete_many({'r': role_id})
		L.log(asab.LOG_NOTICE, "Role unassigned", struct_data={
			"role_id": role_id,
			"deleted_count": result.deleted_count
		})


	async def get_role_tenant(self, role_id):
		"""
		Get the tenant from role ID.
		Verify that the tenant exists, propagate KeyError if it does not.

		:param role_id: Role ID
		:return: Tenant ID
		"""
		match = self.RoleIdRegex.match(role_id)
		if match is not None:
			tenant = match.group(1)
		else:
			L.warning(
				"Role ID contains unallowed characters. "
				"Consider deleting this role and creating a new one.",
				struct_data={"role_id": role_id}
			)
			tenant, _ = role_id.split("/", 1)

		# Verify that tenant exists if the role is not global
		if tenant != "*":
			await self.TenantService.get_tenant(tenant)

		return tenant
