import logging
import re
import typing
from typing import Optional

import asab.storage.exceptions
import asab.exceptions

from ...generic import SessionContext
from ... import exceptions
from ...events import EventTypes
from .view import GlobalRoleView, SharedRoleView, TenantRoleView

#

L = logging.getLogger(__name__)

#


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


	def _prepare_views(self, tenant_id: str | None):
		assert tenant_id != "*"
		views = []
		if tenant_id:
			views.append(SharedRoleView(self.StorageService, self.RoleCollection, tenant_id))
			views.append(TenantRoleView(self.StorageService, self.RoleCollection, tenant_id))
		views.append(GlobalRoleView(self.StorageService, self.RoleCollection))
		return views


	def _role_tenant_id(self, role_id: str):
		tenant_id = role_id.split("/")[0]
		if tenant_id == "*":
			return None
		else:
			return tenant_id


	async def list(
		self,
		tenant_id: Optional[str] = None,
		page: int = 0,
		limit: int = None,
		name_filter: str = None,
		resource_filter: str = None,
	):
		if tenant_id in {"*", None}:
			tenant_id = None
		else:
			self.validate_tenant_access(tenant_id)

		views = self._prepare_views(tenant_id)
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
				limit=limit - len(roles),
				sort=("_id", 1),
				name_filter=name_filter,
				resource_filter=resource_filter,
			):
				roles.append(role)

			if len(roles) >= limit:
				break

			offset = 0

		return {
			"count": sum(counts),
			"data": roles,
		}


	async def _get(self, role_id: str):
		tenant_id = self._role_tenant_id(role_id)
		try:
			if not tenant_id:
				return await GlobalRoleView(self.StorageService, self.RoleCollection).get(role_id)
			try:
				return await TenantRoleView(self.StorageService, self.RoleCollection, tenant_id).get(role_id)
			except KeyError:
				return await SharedRoleView(self.StorageService, self.RoleCollection, tenant_id).get(role_id)
		except KeyError:
			raise exceptions.RoleNotFoundError(role_id)


	async def get(self, role_id: str):
		tenant_id = self._role_tenant_id(role_id)
		if tenant_id:
			self.validate_tenant_access(tenant_id)
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
		shared: bool = False,
		_managed_by: typing.Optional[str] = None,
	):
		tenant_id, role_name = self.parse_role_id(role_id)
		self.validate_role_name(role_name)
		if tenant_id:
			# Does tenant exist?
			await self.TenantService.get_tenant(tenant_id)
			# Does the user have access to the tenant?
			self.validate_tenant_access(tenant_id)
		else:
			# Only superusers can create global roles
			self.validate_superuser_access()

		# Check existence before creating to prevent shadowing shared roles with tenant roles
		try:
			await self._get(role_id)
			raise asab.exceptions.Conflict(key="_id", value=role_id)
		except exceptions.RoleNotFoundError:
			pass

		upsertor = self.StorageService.upsertor(
			self.RoleCollection,
			role_id
		)
		if tenant_id:
			upsertor.set("tenant", tenant_id)
		if resources:
			# TODO: Check global resources, check resource access
			for resource_id in resources:
				try:
					await self.ResourceService.get(resource_id)
				except exceptions.ResourceNotFoundError as e:
					L.log(asab.LOG_NOTICE, "Resource not found.", struct_data={"resource_id": resource_id})
					raise e
			upsertor.set("resources", resources)
		else:
			upsertor.set("resources", [])
		if label:
			upsertor.set("label", label)
		if description:
			upsertor.set("description", description)
		if shared:
			upsertor.set("shared", True)
		if _managed_by:
			upsertor.set("managed_by", _managed_by)

		role_id = await upsertor.execute(event_type=EventTypes.ROLE_CREATED)
		L.log(asab.LOG_NOTICE, "Role created", struct_data={"role_id": role_id})

		self.App.PubSub.publish("Role.created!", role_id=role_id, asynchronously=True)
		return role_id


	def validate_tenant_access(self, tenant_id: str):
		session = SessionContext.get()
		if not (session and session.has_tenant_access(tenant_id)):
			raise exceptions.TenantAccessDeniedError(
				tenant_id, subject=session.Credentials.Id if session else None)


	def validate_superuser_access(self):
		session = SessionContext.get()
		if not (session and session.is_superuser()):
			raise exceptions.AccessDeniedError(
				subject=session.Credentials.Id if session else None, resource="authz:superuser")


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
		# Unassign the role from all credentials
		await self.delete_role_assignments(role_id)

		# Delete the role
		await self.StorageService.delete(self.RoleCollection, role_id)
		L.log(asab.LOG_NOTICE, "Role deleted", struct_data={'role_id': role_id})
		self.App.PubSub.publish("Role.deleted!", role_id=role_id, asynchronously=True)
		return "OK"


	async def update(
		self, role_id: str, *,
		label: str = None,
		description: str = None,
		shared: bool = None,
		resources_to_set: list = None,
		resources_to_add: list = None,
		resources_to_remove: list = None,
		_managed_by: typing.Optional[str] = None,
	):
		# Verify that role exists and validate access
		role_current = await self.get(role_id)

		if not role_current.get("editable", True):
			L.log(asab.LOG_NOTICE, "Role is not editable.", struct_data={"role_id": role_id})
			raise exceptions.NotEditableError("Role is not editable.", role_id=role_id)

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
					message = "Cannot assign global-only resources to tenant roles."
					L.error(message, struct_data={"resource": resource, "role": role_id})
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

		if label is not None:
			upsertor.set("label", label)
			log_data["label"] = label

		if description is not None:
			upsertor.set("description", description)
			log_data["description"] = description

		if shared is not None:
			upsertor.set("shared", bool(shared))
		if _managed_by is not None:
			if not _managed_by:
				upsertor.unset("managed_by")
			else:
				upsertor.set("managed_by", _managed_by)

		await upsertor.execute(event_type=EventTypes.ROLE_UPDATED)
		L.log(asab.LOG_NOTICE, "Role updated", struct_data=log_data)
		self.App.PubSub.publish("Role.updated!", role_id=role_id, asynchronously=True)

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
		if verify_role:
			try:
				await self.get(role_id)
			except KeyError:
				raise exceptions.RoleNotFoundError(role_id)

		tenant, _ = role_id.split("/", 1)
		if verify_tenant and tenant != "*":
			await self.TenantService.get_tenant(tenant)

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
				raise exceptions.TenantNotAssignedError(credentials_id, tenant)

		await self._do_assign_role(credentials_id, role_id, tenant)


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
		assignment_id = "{} {}".format(credentials_id, role_id)
		await self.StorageService.delete(self.CredentialsRolesCollection, assignment_id)
		self.App.PubSub.publish("Role.unassigned!", credentials_id=credentials_id, role_id=role_id, asynchronously=True)
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
