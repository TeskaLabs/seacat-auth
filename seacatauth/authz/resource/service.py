import logging
import re

import asab.storage.exceptions

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
		},
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
				await self.update_description(resource_id, resource_description)


	async def list(self, page: int = 0, limit: int = None):
		collection = self.StorageService.Database[self.ResourceCollection]

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
		data["result"] = "OK"
		return data


	async def create(self, resource_id: str, description: str = None):
		if self.ResourceIdRegex.match(resource_id) is None:
			L.error("Invalid ID format", struct_data={"resource_id": resource_id})
			return {
				"result": "INVALID-VALUE",
				"message":
					"Resource ID must consist only of characters 'a-z0-9.:_-', "
					"start with a letter, end with a letter or digit, "
					"and be between 2 and 128 characters long.",
			}

		upsertor = self.StorageService.upsertor(self.ResourceCollection, obj_id=resource_id)

		if description is not None:
			upsertor.set("description", description)

		try:
			await upsertor.execute()
			L.log(asab.LOG_NOTICE, "Resource created", struct_data={"resource_id": resource_id})
		except asab.storage.exceptions.DuplicateError:
			L.warning("Resource already exists", struct_data={"resource_id": resource_id})
			return {
				"result": "CONFLICT",
				"message": "Resource already exists",
			}

		return {"result": "OK"}


	async def update_description(self, resource_id: str, description: str):
		try:
			resource = await self.get(resource_id)
		except KeyError:
			L.error("Resource not found", struct_data={"resource_id": resource_id})
			return {
				"result": "NOT-FOUND",
				"message": "Resource '{}' not found".format(resource_id),
			}

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

		try:
			await upsertor.execute()
			L.log(asab.LOG_NOTICE, "Resource description updated", struct_data={
				"resource_id": resource_id,
				"description": description,
			})
		except KeyError:
			L.error("Resource not found", struct_data={"resource_id": resource_id})
			return {
				"result": "NOT-FOUND",
				"message": "Resource '{}' not found".format(resource_id),
			}

		return {"result": "OK"}
