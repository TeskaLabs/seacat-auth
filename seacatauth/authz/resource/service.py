import logging
import re
import typing

import asab.storage.exceptions

#

L = logging.getLogger(__name__)

#


class ResourceService(asab.Service):

	ResourceCollection = "rs"
	# Resource name format: "{module}:{submodule}:{...}:{resource_name}"
	ResourceIdRegex = re.compile(r"^((?:[a-zA-Z0-9_-]+:)*[a-zA-Z0-9_-]+):([a-zA-Z0-9_-]+)$")
	# TODO: gather these system resources automatically
	BuiltinResources = [
		"seacat:access",
		"authz:superuser",
		"authz:tenant:admin",
		"authz:credentials:admin",
	]

	def __init__(self, app, service_name="seacatauth.ResourceService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")

	async def initialize(self, app):
		await super().initialize(app)
		await self._ensure_builtin_resources()

	async def _ensure_builtin_resources(self):
		"""
		Check if all builtin resources exist. Create them if they don't.
		"""
		for res_id in self.BuiltinResources:
			L.info("Checking for builtin resource '{}'".format(res_id))
			try:
				await self.get(res_id)
			except KeyError:
				await self.create(res_id)
			except Exception as e:
				L.error("Cannot create builtin resource '{}': {}".format(res_id, e))
				raise e

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
				"result": "ERROR",
				"message": "Invalid resource ID",
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


	async def update_description(self, resource_id: str, description: typing.Union[str, None]):
		if self.ResourceIdRegex.match(resource_id) is None:
			L.error("Invalid ID format", struct_data={"resource_id": resource_id})
			return {
				"result": "ERROR",
				"message": "Invalid resource ID",
			}

		upsertor = self.StorageService.upsertor(self.ResourceCollection, obj_id=resource_id)

		if description is not None:
			upsertor.set("description", description)
		else:
			upsertor.unset("description")

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
