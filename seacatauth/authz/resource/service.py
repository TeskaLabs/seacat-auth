import logging
import re
import asab.storage.exceptions
import asab
import asab.exceptions

from ... import exceptions
from ...api import local_authz
from ...events import EventTypes
from ...models.const import ResourceId


L = logging.getLogger(__name__)


SEACAT_AUTH_RESOURCES = {
	ResourceId.SUPERUSER: {
		"description": "Grants superuser access, including the access to all tenants.",
		"global_only": True,
	},
	ResourceId.IMPERSONATE: {
		"description": "Open a session as a different user.",
		"global_only": True,
	},
	ResourceId.ACCESS_ALL_TENANTS: {
		"description": "Grants access to all tenants.",
		"global_only": True,
	},
	ResourceId.CREDENTIALS_ACCESS: {
		"description": "List credentials and view credentials details.",
	},
	ResourceId.CREDENTIALS_EDIT: {
		"description": "Edit and suspend credentials.",
	},
	ResourceId.SESSION_ACCESS: {
		"description": "List sessions and view session details.",
		"global_only": True,
	},
	ResourceId.SESSION_TERMINATE: {
		"description": "Terminate sessions.",
		"global_only": True,
	},
	ResourceId.RESOURCE_ACCESS: {
		"description": "List resources and view resource details.",
		"global_only": True,
	},
	ResourceId.RESOURCE_EDIT: {
		"description": "Edit and delete resources.",
		"global_only": True,
	},
	ResourceId.CLIENT_ACCESS: {
		"description": "List clients and view client details.",
		"global_only": True,
	},
	ResourceId.CLIENT_EDIT: {
		"description": "Edit and delete clients.",
		"global_only": True,
	},
	ResourceId.TENANT_ACCESS: {
		"description": "List tenants, view tenant detail and see tenant members.",
	},
	ResourceId.TENANT_CREATE: {
		"description": "Create new tenants.",
		"global_only": True,
	},
	ResourceId.TENANT_EDIT: {
		"description": "Edit tenant data.",
	},
	ResourceId.TENANT_DELETE: {
		"description": "Delete tenant.",
	},
	ResourceId.TENANT_ASSIGN: {
		"description": "Assign and unassign tenant members, invite new users to tenant.",
	},
	ResourceId.ROLE_ACCESS: {
		"description": "Search tenant roles, view role detail and list role bearers.",
	},
	ResourceId.ROLE_EDIT: {
		"description":
			"Create, edit and delete tenant roles. "
			"This does not enable the bearer to assign Seacat system resources.",
	},
	ResourceId.ROLE_ASSIGN: {
		"description": "Assign and unassign tenant roles.",
	},
}


class ResourceService(asab.Service):

	ResourceCollection = "rs"
	# Resource name format: "{module}:{submodule}:..."
	ResourceNamePattern = r"[a-z][a-z0-9:._-]{0,128}[a-z0-9]"

	def __init__(self, app, service_name="seacatauth.ResourceService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.ResourceIdRegex = re.compile("^{}$".format(self.ResourceNamePattern))


	async def initialize(self, app):
		await super().initialize(app)
		with local_authz(self.Name, resources={ResourceId.SUPERUSER}):
			await self._ensure_builtin_resources()


	async def is_global_only_resource(self, resource_id):
		resource = await self.get(resource_id)
		return resource.get("global_only", False)


	async def _ensure_builtin_resources(self):
		"""
		Check if all builtin resources exist. Create them if they don't.
		Update their descriptions if they are outdated.
		"""
		for resource_id, resource_config in SEACAT_AUTH_RESOURCES.items():
			try:
				db_resource = await self.get(resource_id)
			except KeyError:
				await self.create(resource_id, **resource_config, is_managed_by_seacat_auth=True)
				continue

			for k, v in resource_config.items():
				if db_resource.get(k) != v:
					await self._update(db_resource, **resource_config, is_managed_by_seacat_auth=True)
					continue


	async def list(self, page: int = 0, limit: int = None, query_filter: dict = None):
		collection = self.StorageService.Database[self.ResourceCollection]

		if query_filter is None:
			query_filter = {}
		cursor = collection.find(query_filter)

		cursor.sort("_id", 1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		resources = []
		count = await collection.count_documents(query_filter)
		async for resource_dict in cursor:
			resources.append(self.normalize_resource(resource_dict))

		return {
			"data": resources,
			"count": count,
		}


	async def get(self, resource_id: str):
		try:
			resource = await self.StorageService.get(self.ResourceCollection, resource_id)
		except KeyError:
			raise exceptions.ResourceNotFoundError(resource_id)
		return self.normalize_resource(resource)


	async def create(
		self,
		resource_id: str,
		description: str = None,
		global_only: bool = None,
		is_managed_by_seacat_auth: bool = False
	):
		if self.ResourceIdRegex.match(resource_id) is None:
			raise asab.exceptions.ValidationError(
				"Resource ID must consist only of characters 'a-z0-9.:_-', "
				"start with a letter, end with a letter or digit, "
				"and be between 2 and 128 characters long.")
		upsertor = self.StorageService.upsertor(self.ResourceCollection, obj_id=resource_id)

		if description is not None:
			upsertor.set("description", description)

		if global_only is True:
			upsertor.set("global_only", True)

		if is_managed_by_seacat_auth:
			upsertor.set("managed_by", "seacat-auth")

		try:
			await upsertor.execute(event_type=EventTypes.RESOURCE_CREATED)
		except asab.storage.exceptions.DuplicateError as e:
			if e.KeyValue is not None:
				key, value = e.KeyValue.popitem()
				raise asab.exceptions.Conflict(key=key, value=value)
			else:
				raise asab.exceptions.Conflict()

		L.log(asab.LOG_NOTICE, "Resource created", struct_data={"resource": resource_id})


	async def update(self, resource_id: str, description: str):
		resource = await self.get(resource_id)
		assert_resource_is_editable(resource)
		await self._update(resource, description)


	async def _update(
		self,
		resource: dict,
		description: str = None,
		global_only: bool = None,
		is_managed_by_seacat_auth: bool = False
	):
		upsertor = self.StorageService.upsertor(
			self.ResourceCollection,
			obj_id=resource["_id"],
			version=resource["_v"])

		if description is None:
			pass
		elif description == "":
			upsertor.unset("description")
		else:
			upsertor.set("description", description)

		if global_only is None:
			pass
		elif global_only is False:
			upsertor.unset("global_only")
		elif global_only is True:
			upsertor.set("global_only", True)
		else:
			raise ValueError("global_only must be a boolean value.")

		if is_managed_by_seacat_auth:
			upsertor.set("managed_by", "seacat-auth")

		await upsertor.execute(event_type=EventTypes.RESOURCE_UPDATED)
		L.log(asab.LOG_NOTICE, "Resource updated", struct_data={"resource": resource["_id"]})


	async def delete(self, resource_id: str, hard_delete: bool = False):
		resource = await self.get(resource_id)
		assert_resource_is_editable(resource)

		# Remove the resource from all roles
		role_svc = self.App.get_service("seacatauth.RoleService")
		roles = await role_svc.list_roles(resource_filter=resource_id)
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
		# Get existing resource details and roles
		resource = await self.get(resource_id)
		assert_resource_is_editable(resource)

		role_svc = self.App.get_service("seacatauth.RoleService")
		roles = await role_svc.list_roles(resource_filter=resource_id)

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


	def normalize_resource(self, resource: dict):
		if resource["_id"] in SEACAT_AUTH_RESOURCES or resource.get("managed_by"):
			resource["read_only"] = True
		return resource


def assert_resource_is_editable(resource: dict):
	if resource.get("read_only"):
		L.log(asab.LOG_NOTICE, "Resource is not editable.", struct_data={"resource_id": resource["_id"]})
		raise exceptions.NotEditableError("Resource is not editable.")
	return True
