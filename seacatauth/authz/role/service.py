import logging
import re
from typing import Optional

import asab.storage.exceptions

from ...tenant import TenantService

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
		# TODO: Tenant name should be validated by tenant service
		self.RoleIdRegex = re.compile(r"^([^/]+)/({role})$".format(
			role=self.RoleNamePattern
		))

	async def list(self, tenant: Optional[str] = None, page: int = 0, limit: int = None):
		collection = self.StorageService.Database[self.RoleCollection]
		if tenant is not None:
			query_filter = {"tenant": {"$in": [tenant, None]}}
		else:
			query_filter = {}
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
		result = await self.StorageService.get(self.RoleCollection, role_id)
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
		tenant = await self.get_tenant_from_role_id(role_id)

		upsertor = self.StorageService.upsertor(
			self.RoleCollection,
			role_id
		)
		upsertor.set("resources", [])
		if tenant != "*":
			upsertor.set("tenant", tenant)
		try:
			await upsertor.execute()
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

	async def update_resources(
		self, role_id: str,
		resources_to_set: Optional[list] = None,
		resources_to_add: Optional[list] = None,
		resources_to_remove: Optional[list] = None
	):
		tenant = await self.get_tenant_from_role_id(role_id)

		resources_to_assign = set().union(
			resources_to_set or [],
			resources_to_add or [],
			resources_to_remove or []
		)
		if tenant != "*":
			# TENANT role
			# Resource "authz:superuser" cannot be assigned to a tenant role
			if "authz:superuser" in resources_to_assign:
				message = "Cannot assign resource 'authz:superuser' to a tenant role ({}).".format(role_id)
				L.warning(message)
				raise ValueError(message)

		role_current = await self.StorageService.get(self.RoleCollection, role_id)
		if role_current is not None:
			version = role_current["_v"]
		else:
			version = 0
		upsertor = self.StorageService.upsertor(
			self.RoleCollection,
			role_id,
			version=version
		)
		if resources_to_set is not None:
			resources_to_set = set(resources_to_set)
			# Check if resource exists, otherwise raise KeyError
			for res_id in resources_to_set:
				try:
					await self.ResourceService.get(res_id)
				except KeyError:
					message = "Unknown resource: '{}'".format(res_id)
					L.warning(message)
					raise KeyError(message)
			upsertor.set("resources", list(resources_to_set))

		# TODO: add and remove, check for duplicate entries
		# if resources_to_add is not None:
		# 	for res in resources_to_add:
		# 		upsertor.push("resources", res)
		# if resources_to_remove is not None:
		# 	for res in resources_to_remove:
		# 		upsertor.pull("resources", res)  # TODO: implement MongoUpsertor.pull()

		await upsertor.execute()
		L.log(asab.LOG_NOTICE, "Resources assigned", struct_data={
			'role': role_id,
			'set': resources_to_set,
			'add': resources_to_add,
			'del': resources_to_remove
		})
		return "OK"

	async def get_roles_by_credentials(self, credentials_id: str, tenant: str = None):
		"""
		Returns a list of roles assigned to the given `credentials_id`.
		Includes roles that match the given `tenant` plus global roles.
		"""
		result = []
		coll = await self.StorageService.collection(self.CredentialsRolesCollection)
		async for obj in coll.find({
			'c': credentials_id,
			't': {"$in": [tenant, None]}
		}):
			result.append(obj["r"])
		return result

	async def set_roles(self, credentials_id: str, tenant_scope: set, roles: list):
		"""
		Assign `roles` list to a given `credentials_id` and unassign all current roles that are not listed in `roles`.
		Only roles within the `tenant_scope` can be un/assigned.
		"""
		# Validate that requested credentials exist
		try:
			await self.CredentialService.get(credentials_id=credentials_id)
		except KeyError:
			message = "Credentials not found"
			L.error(message, struct_data={"cid": credentials_id})
			raise KeyError(message)

		# Validate that requested credentials have access to roles' tenants
		# Remove invalid tenants from the tenant scope
		if self.TenantService.is_enabled():
			cred_tenants = await self.TenantService.get_tenants(credentials_id)
			unavailable_tenants = set()
			for tenant in tenant_scope:
				if tenant == "*":
					continue
				if tenant not in cred_tenants:
					unavailable_tenants.add(tenant)
			tenant_scope.difference_update(unavailable_tenants)
		else:
			# Tenant service is not enabled: Only global roles can be assigned
			if tenant_scope != set("*"):
				message = "Assigning tenant roles in tenantless mode"
				L.error(message)
				raise ValueError(message)

		if len(tenant_scope) == 0:
			message = "No valid tenants"
			L.error(message)
			raise ValueError(message)

		# Validate all requested roles
		roles_to_assign = set()
		for role in roles:
			# Validate by regex
			role_tenant = await self.get_tenant_from_role_id(role)

			# Validate by current tenant scope
			if role_tenant not in tenant_scope:
				# Role is outside current tenant scope
				if role_tenant == "*":
					# "*" is not in scope, so global roles are simply ignored without raising an error
					continue
				# Roles from unexpected tenant raise error
				message = "Role doesn't match requested tenants"
				L.warning(message, struct_data={
					"role": role,
					"tenants": list(tenant_scope)
				})
				raise ValueError(message)

			# Validate that role exists
			try:
				await self.get(role_id=role)
			except KeyError:
				message = "Role not found"
				L.error(message, struct_data={"role": role})
				raise KeyError(message)

			roles_to_assign.add(role)

		# Get current roles
		tenant_query = [None if tenant == "*" else tenant for tenant in tenant_scope]
		coll = await self.StorageService.collection(self.CredentialsRolesCollection)

		# {"t": {"$in": [None]}} matches entries with the "t" field missing, i.e. global roles
		# {"t": {"$in": ["tenant-1", None]}} matches both global roles and "tenant-1" roles
		query = {"c": credentials_id, "t": {"$in": tenant_query}}

		# Unassign roles that are not among the requested roles
		assignments_to_remove = []
		async for obj in coll.find(query):
			if obj['r'] not in roles_to_assign:
				assignments_to_remove.append(obj['_id'])
			else:
				# The role is already assigned
				roles_to_assign.remove(obj['r'])

		if len(assignments_to_remove) > 0:
			await coll.delete_many({'_id': {'$in': assignments_to_remove}})

		# Assign new roles
		for role in roles_to_assign:
			crid = "{} {}".format(credentials_id, role)
			upsertor = self.StorageService.upsertor(self.CredentialsRolesCollection, obj_id=crid)
			upsertor.set("c", credentials_id)
			upsertor.set("r", role)

			tenant = await self.get_tenant_from_role_id(role)
			if tenant != "*":
				upsertor.set("t", tenant)
			await upsertor.execute()

		L.log(asab.LOG_NOTICE, "Roles assigned", struct_data={
			"cid": credentials_id,
			"tenants": list(tenant_scope),
			"assigned": list(roles_to_assign),
			"unassigned": [assignment.split(" ")[-1] for assignment in assignments_to_remove]
		})

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


	async def assign_role(self, credentials_id: str, role_id: str):
		tenant = await self.get_tenant_from_role_id(role_id)

		# Check if credentials exist
		try:
			await self.CredentialService.detail(credentials_id)
		except KeyError:
			message = "Credentials not found"
			L.warning(message, struct_data={"cid": credentials_id})
			return {
				"result": "NOT-FOUND",
				"message": message,
			}

		# Check if role exists
		try:
			await self.get(role_id)
		except KeyError:
			message = "Role not found"
			L.warning(message, struct_data={"role": role_id})
			return {
				"result": "NOT-FOUND",
				"message": message,
			}

		return await self._do_assign_role(credentials_id, role_id, tenant)


	async def _do_assign_role(self, credentials_id: str, role_id: str, tenant: str):
		assignment_id = "{} {}".format(credentials_id, role_id)

		upsertor = self.StorageService.upsertor(self.CredentialsRolesCollection, obj_id=assignment_id)
		upsertor.set("c", credentials_id)
		upsertor.set("r", role_id)
		if tenant != "*":
			upsertor.set("t", tenant)

		try:
			await upsertor.execute()
		except asab.storage.exceptions.DuplicateError:
			message = "Role already assigned to these credentials"
			L.warning(message, struct_data={"cid": credentials_id, "role": role_id})
			return {
				"result": "ALREADY-EXISTS",
				"message": message,
			}

		L.log(asab.LOG_NOTICE, "Role assigned", struct_data={
			"cid": credentials_id,
			"role": role_id,
		})
		return {"result": "OK"}


	async def unassign_role(self, credentials_id: str, role_id: str):
		assignment_id = "{} {}".format(credentials_id, role_id)

		try:
			await self.StorageService.delete(self.CredentialsRolesCollection, assignment_id)
		except KeyError:
			message = "Credentials are not assigned to this role"
			L.warning(message, struct_data={"cid": credentials_id, "role": role_id})
			return {
				"result": "NOT-FOUND",
				"message": message,
			}

		L.log(asab.LOG_NOTICE, "Role unassigned", struct_data={
			"cid": credentials_id,
			"role": role_id,
		})
		return {"result": "OK"}


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


	async def get_tenant_from_role_id(self, role_id):
		match = self.RoleIdRegex.match(role_id)
		if match is not None:
			tenant = match.group(1)
			# Verify that tenant exists if the role is not global
			if tenant != "*":
				await self.TenantService.get_tenant(tenant)
		else:
			L.warning(
				"Role ID contains unallowed characters. "
				"Consider deleting this role and creating a new one.",
				struct_data={"role_id": role_id}
			)
			tenant, _ = role_id.split("/", 1)
		return tenant
