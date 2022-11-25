import logging
import re

import asab.storage.exceptions
import asab.exceptions

#

L = logging.getLogger(__name__)

#


class ResourceService(asab.Service):

	ResourceCollection = "rs"
	# Resource name format: "{module}:{submodule}:..."
	ResourceNamePattern = r"[a-z][a-z0-9:._-]{0,128}[a-z0-9]"

	# TODO: gather these system resources automatically
	BuiltinResources = [
		{
			"id": "seacat:access",
			"description": "Grants access to Seacat API and Seacat WebUI.",
		},
		{
			"id": "authz:superuser",
			"description": "Grants superuser access, including the access to all tenants.",
		},
		{
			"id": "authz:tenant:admin",
			"description": "Grants administrative rights for the tenant through which this resource is assigned.",
		}
	]


	def __init__(self, app, service_name="seacatauth.ResourceService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.ResourceIdRegex = re.compile("^{}$".format(self.ResourceNamePattern))


	async def initialize(self, app):
		await super().initialize(app)
		await self._ensure_builtin_resources()


	async def _ensure_builtin_resources(self):
		"""
		Check if all builtin resources exist. Create them if they don't.
		Update their descriptions if they are outdated.
		"""
		for resource_config in self.BuiltinResources:
			resource_id = resource_config["id"]
			resource_description = resource_config.get("description")

			L.info("Checking for builtin resource '{}'".format(resource_id))
			try:
				db_resource = await self.get(resource_id)
			except KeyError:
				await self.create(resource_id, resource_description)
				continue
			except Exception as e:
				L.error("Cannot create builtin resource '{}'".format(resource_id))
				raise e

			# Update resource description
			if resource_description is not None and db_resource.get("description") != resource_description:
				await self.update(resource_id, resource_description)


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
			resources.append(resource_dict)

		return {
			"result": "OK",
			"data": resources,
			"count": count,
		}


	async def get(self, resource_id: str):
		data = await self.StorageService.get(self.ResourceCollection, resource_id)
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
			await upsertor.execute()
		except asab.storage.exceptions.DuplicateError as e:
			if e.KeyValue is not None:
				key, value = e.KeyValue
				raise asab.exceptions.Conflict(key=key, value=value)
			else:
				raise asab.exceptions.Conflict()

		L.log(asab.LOG_NOTICE, "Resource created", struct_data={"resource": resource_id})


	async def update(self, resource_id: str, description: str):
		resource = await self.get(resource_id)
		upsertor = self.StorageService.upsertor(
			self.ResourceCollection,
			obj_id=resource_id,
			version=resource["_v"]
		)

		assert description is not None

		if description == "":
			upsertor.unset("description")
		else:
			upsertor.set("description", description)

		await upsertor.execute()
		L.log(asab.LOG_NOTICE, "Resource description updated", struct_data={"resource": resource_id})


	async def delete(self, resource_id: str, hard_delete: bool = False):
		if resource_id in map(lambda x: x["id"], self.BuiltinResources):
			raise ValueError("System resource cannot be deleted")

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
			await upsertor.execute()
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
		await upsertor.execute()
		L.log(asab.LOG_NOTICE, "Resource undeleted", struct_data={
			"resource": resource_id,
		})


	async def rename(self, resource_id: str, new_resource_id: str):
		"""
		Shortcut for creating a new resource with the desired name,
		assigning it to roles that have the original resource and deleting the original resource
		"""
		if resource_id in map(lambda x: x["id"], self.BuiltinResources):
			raise ValueError("System resource cannot be renamed")

		role_svc = self.App.get_service("seacatauth.RoleService")

		resource = await self.get(resource_id)
		await self.create(new_resource_id, resource["description"])

		roles = await role_svc.list(resource=resource_id)
		if roles["count"] > 0:
			for role in roles["data"]:
				await role_svc.update(
					role["_id"],
					resources_to_remove=[resource_id],
					resources_to_add=[new_resource_id])

		await self.StorageService.delete(self.ResourceCollection, resource_id)
		L.log(asab.LOG_NOTICE, "Resource renamed", struct_data={
			"old_resource": resource_id,
			"new_resource": resource_id,
			"n_roles": roles["count"],
		})
