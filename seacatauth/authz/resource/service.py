import logging
import re

import asab.storage.exceptions
import asab
import asab.exceptions

from ...events import EventTypes

#

L = logging.getLogger(__name__)

#


class ResourceService(asab.Service):

	ResourceCollection = "rs"
	# Resource name format: "{module}:{submodule}:..."
	ResourceNamePattern = r"[a-z][a-z0-9:._-]{0,128}[a-z0-9]"

	# TODO: gather these system resources automatically
	_BuiltinResources = {
		"seacat:access": {
			"description": "Access to Seacat Admin API and UI.",
		},
		"authz:superuser": {
			"description": "Grants superuser access, including the access to all tenants.",
		},
		"authz:impersonate": {
			"description": "Open a session as a different user.",
		},
		"authz:tenant:access": {
			"description": "Grants non-superuser access to all tenants.",
		},
		"seacat:credentials:access": {
			"description": "List credentials and view credentials details.",
		},
		"seacat:credentials:edit": {
			"description": "Edit and suspend credentials.",
		},
		"seacat:session:access": {
			"description": "List sessions and view session details.",
		},
		"seacat:session:terminate": {
			"description": "Terminate sessions.",
		},
		"seacat:resource:access": {
			"description": "List resources and view resource details.",
		},
		"seacat:resource:edit": {
			"description": "Edit and delete resources.",
		},
		"seacat:client:access": {
			"description": "List clients and view client details.",
		},
		"seacat:client:edit": {
			"description": "Edit and delete clients.",
		},
		"seacat:tenant:access": {
			"description": "List tenants, view tenant detail and see tenant members.",
		},
		# "seacat:tenant:create": {  # Requires superuser for now
		# 	"description": "Create new tenants.",
		# },
		"seacat:tenant:edit": {
			"description": "Edit tenant data.",
		},
		"seacat:tenant:delete": {
			"description": "Delete tenant.",
		},
		"seacat:tenant:assign": {
			"description": "Assign and unassign tenant members.",
		},
		"seacat:role:access": {
			"description": "Search tenant roles, view role detail and list role bearers.",
		},
		"seacat:role:edit": {
			"description":
				"Create, edit and delete tenant roles. "
				"This does not enable the bearer to assign Seacat system resources.",
		},
		"seacat:role:assign": {
			"description": "Assign and unassign tenant roles.",
		},
	}
	GlobalOnlyResources = frozenset({
		"authz:superuser", "authz:impersonate", "authz:tenant:access", "seacat:credentials:access", "seacat:credentials:edit",
		"seacat:session:access", "seacat:session:terminate", "seacat:resource:access", "seacat:resource:edit",
		"seacat:client:access", "seacat:client:edit", "seacat:tenant:create"})


	def __init__(self, app, service_name="seacatauth.ResourceService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.ResourceIdRegex = re.compile("^{}$".format(self.ResourceNamePattern))


	async def initialize(self, app):
		await super().initialize(app)
		await self._ensure_builtin_resources()


	def is_builtin_resource(self, resource_id):
		return resource_id in self._BuiltinResources


	def is_global_only_resource(self, resource_id):
		return resource_id in self.GlobalOnlyResources


	async def _ensure_builtin_resources(self):
		"""
		Check if all builtin resources exist. Create them if they don't.
		Update their descriptions if they are outdated.
		"""
		for resource_id, resource_config in self._BuiltinResources.items():
			description = resource_config.get("description")

			L.debug("Checking for built-in resource {!r}".format(resource_id))
			try:
				db_resource = await self.get(resource_id)
			except KeyError:
				await self.create(resource_id, description)
				continue

			# Update resource description
			if description is not None and db_resource.get("description") != description:
				await self._update(resource_id, description)


	async def list(self, page: int = 0, limit: int = None, query_filter: dict = None):
		collection = self.StorageService.Database[self.ResourceCollection]

		if query_filter is None:
			query_filter = {}
		cursor = collection.find(query_filter)

		cursor.sort("_c", -1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		resources = []
		count = await collection.count_documents(query_filter)
		async for resource_dict in cursor:
			if self.is_builtin_resource(resource_dict["_id"]):
				resource_dict["editable"] = False
			if self.is_global_only_resource(resource_dict["_id"]):
				resource_dict["global_only"] = True
			resources.append(resource_dict)

		return {
			"data": resources,
			"count": count,
		}


	async def get(self, resource_id: str):
		data = await self.StorageService.get(self.ResourceCollection, resource_id)
		if self.is_builtin_resource(data["_id"]):
			data["editable"] = False
		if self.is_global_only_resource(data["_id"]):
			data["global_only"] = True
		return data


	async def create(self, resource_id: str, description: str = None):
		if self.ResourceIdRegex.match(resource_id) is None:
			raise asab.exceptions.ValidationError(
				"Resource ID must consist only of characters 'a-z0-9.:_-', "
				"start with a letter, end with a letter or digit, "
				"and be between 2 and 128 characters long.")
		upsertor = self.StorageService.upsertor(self.ResourceCollection, obj_id=resource_id)

		if description is not None:
			upsertor.set("description", description)

		try:
			await upsertor.execute(event_type=EventTypes.RESOURCE_CREATED)
		except asab.storage.exceptions.DuplicateError as e:
			if e.KeyValue is not None:
				key, value = e.KeyValue
				raise asab.exceptions.Conflict(key=key, value=value)
			else:
				raise asab.exceptions.Conflict()

		L.log(asab.LOG_NOTICE, "Resource created", struct_data={"resource": resource_id})


	async def _update(self, resource_id: str, description: str):
		resource = await self.get(resource_id)
		upsertor = self.StorageService.upsertor(
			self.ResourceCollection,
			obj_id=resource_id,
			version=resource["_v"])

		assert description is not None
		if description == "":
			upsertor.unset("description")
		else:
			upsertor.set("description", description)

		await upsertor.execute(event_type=EventTypes.RESOURCE_UPDATED)
		L.log(asab.LOG_NOTICE, "Resource updated", struct_data={"resource": resource_id})


	async def update(self, resource_id: str, description: str):
		if self.is_builtin_resource(resource_id):
			raise asab.exceptions.ValidationError("Built-in resource cannot be modified")
		await self._update(resource_id, description)


	async def delete(self, resource_id: str, hard_delete: bool = False):
		if self.is_builtin_resource(resource_id):
			raise asab.exceptions.ValidationError("Built-in resource cannot be deleted")

		resource = await self.get(resource_id)

		# Remove the resource from all roles
		role_svc = self.App.get_service("seacatauth.RoleService")
		roles = await role_svc.list(resource=resource_id)
		if roles["count"] > 0:
			for role in roles["data"]:
				await role_svc.update(role["_id"], resources_to_remove=[resource_id])
			L.log(asab.LOG_NOTICE, "Resource unassigned", struct_data={
				"resource": resource_id,
				"n_roles": roles["count"],
			})

		if hard_delete:
			await self.StorageService.delete(self.ResourceCollection, resource_id)
			L.warning("Resource deleted", struct_data={
				"resource": resource_id,
			})
		else:
			upsertor = self.StorageService.upsertor(
				self.ResourceCollection,
				obj_id=resource_id,
				version=resource["_v"]
			)
			upsertor.set("deleted", True)
			await upsertor.execute(event_type=EventTypes.RESOURCE_DELETED)
			L.log(asab.LOG_NOTICE, "Resource soft-deleted", struct_data={
				"resource": resource_id,
			})


	async def undelete(self, resource_id: str):
		resource = await self.get(resource_id)
		if resource.get("deleted") is not True:
			raise asab.exceptions.Conflict("Cannot undelete a resource that has not been soft-deleted.")

		upsertor = self.StorageService.upsertor(
			self.ResourceCollection,
			obj_id=resource_id,
			version=resource["_v"]
		)
		upsertor.unset("deleted")
		await upsertor.execute(event_type=EventTypes.RESOURCE_UNDELETED)
		L.log(asab.LOG_NOTICE, "Resource undeleted", struct_data={
			"resource": resource_id,
		})


	async def rename(self, resource_id: str, new_resource_id: str):
		"""
		Shortcut for creating a new resource with the desired name,
		assigning it to roles that have the original resource and deleting the original resource
		"""
		if self.is_builtin_resource(resource_id):
			raise asab.exceptions.ValidationError("Built-in resource cannot be renamed")

		role_svc = self.App.get_service("seacatauth.RoleService")

		# Get existing resource details and roles
		resource = await self.get(resource_id)
		roles = await role_svc.list(resource=resource_id)

		# Delete existing resource
		await self.StorageService.delete(self.ResourceCollection, resource_id)

		# Create a new resource and assign it to the original one's roles
		await self.create(new_resource_id, resource.get("description"))
		if roles["count"] > 0:
			for role in roles["data"]:
				await role_svc.update(
					role["_id"],
					resources_to_remove=[resource_id],
					resources_to_add=[new_resource_id])

		L.log(asab.LOG_NOTICE, "Resource renamed", struct_data={
			"old_resource": resource_id,
			"new_resource": resource_id,
			"n_roles": roles["count"],
		})
