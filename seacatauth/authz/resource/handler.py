import logging
import re
import aiohttp.web
import asab
import asab.web.rest
import asab.exceptions

from ... import exceptions
from ...decorators import access_control


L = logging.getLogger(__name__)


class ResourceHandler(object):
	"""
	Resource management

	---
	tags: ["Resources"]
	"""

	def __init__(self, app, rbac_svc):
		self.RBACService = rbac_svc
		self.ResourceService = app.get_service("seacatauth.ResourceService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/resource", self.list)
		web_app.router.add_get("/resource/{resource_id}", self.get)
		web_app.router.add_post("/resource/{resource_id}", self.create_or_undelete)
		web_app.router.add_put("/resource/{resource_id}", self.update)
		web_app.router.add_delete("/resource/{resource_id}", self.delete)


	async def list(self, request):
		"""
		List resources

		---
		parameters:
		-	name: p
			in: query
			description: Page number
			schema:
				type: integer
		-	name: i
			in: query
			description: Items per page
			schema:
				type: integer
		-	name: f
			in: query
			description: Filter string
			schema:
				type: string
		-	name: exclude
			in: query
			description:
				Exclude resources based on their type/status. If omitted, this parameter defaults
				to `exclude=deleted`, which means the results include all active resources.
			required: false
			explode: false
			schema:
				type: array
				items:
					enum: ["active", "deleted", "globalonly"]
		"""
		page = int(request.query.get("p", 1)) - 1
		limit = request.query.get("i", None)
		if limit is not None:
			limit = int(limit)

		# Filter by ID.startswith()
		query_filter = {}
		name_filter = request.query.get("f")
		if name_filter:
			query_filter["_id"] = {"$regex": re.escape(name_filter)}

		# Get the types of resources to exclude from the results
		# By default, exclude only deleted resources
		exclude = request.query.get("exclude", "")
		if len(exclude) == 0:
			exclude = "deleted"
		exclude = exclude.split(",")
		if "deleted" in exclude:
			if "active" in exclude:
				return asab.web.rest.json_response(request, {"data": [], "count": 0})
			else:
				query_filter["deleted"] = {"$in": [None, False]}
		else:
			if "active" in exclude:
				query_filter["deleted"] = True
			else:
				pass

		if "globalonly" in exclude:
			if "_id" not in query_filter:
				query_filter["_id"] = {}
			query_filter["_id"]["$nin"] = list(self.ResourceService.GlobalOnlyResources)

		resources = await self.ResourceService.list(page, limit, query_filter)
		return asab.web.rest.json_response(request, resources)


	async def get(self, request):
		"""
		Get resource detail
		"""
		resource_id = request.match_info["resource_id"]
		result = await self.ResourceService.get(resource_id)
		return asab.web.rest.json_response(
			request, result
		)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"additionalProperties": False,
		"properties": {
			"description": {"type": "string"}}
	})
	@access_control("seacat:resource:edit")
	async def create_or_undelete(self, request, *, json_data):
		"""
		Create a new resource or undelete a resource that has been soft-deleted
		"""
		resource_id = request.match_info["resource_id"]

		try:
			resource = await self.ResourceService.get(resource_id)
			# Resource exists: can it be undeleted?
			if resource.get("deleted") in [None, False]:
				raise asab.exceptions.Conflict("Resource already exists.", key="_id", value=resource_id)
			undelete = True
		except KeyError:
			undelete = False

		if undelete:
			await self.ResourceService.undelete(resource_id)
		else:
			await self.ResourceService.create(resource_id, json_data.get("description"))
		return asab.web.rest.json_response(request, {"result": "OK"})


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"additionalProperties": False,
		"properties": {
			"name": {"type": "string"},
			"description": {"type": "string"},
		}
	})
	@access_control("seacat:resource:edit")
	async def update(self, request, *, json_data):
		"""
		Update resource description or rename resource
		"""
		resource_id = request.match_info["resource_id"]
		if "description" in json_data:
			try:
				await self.ResourceService.update(resource_id, json_data["description"])
			except exceptions.NotEditableError as e:
				return e.json_response(request)
		if "name" in json_data and json_data["name"] != resource_id:
			# TODO: Renaming should be on a separate endpoint
			try:
				await self.ResourceService.rename(resource_id, json_data["name"])
			except exceptions.NotEditableError as e:
				return e.json_response(request)

		return asab.web.rest.json_response(request, {"result": "OK"})


	@access_control("seacat:resource:edit")
	async def delete(self, request, *, credentials_id):
		"""
		Delete resource

		The resource is soft-deleted (suspended) by default.

		---
		parameters:
		-	name: hard_delete
			in: query
			description:
				By default, the resource is only soft-deleted, i.e. marked as deleted and retained in te database.
				Enabling this switch causes the resource to be completely removed from the database.
				Hard-deleting requires `authz:superuser`.
			required: false
			schema:
				type: boolean
				enum: ["true"]
		"""
		resource_id = request.match_info["resource_id"]
		hard_delete = request.query.get("hard_delete") == "true"
		if hard_delete and not request.is_superuser:
			L.log(asab.LOG_NOTICE, "Cannot hard-delete resources without superuser rights", struct_data={
				"cid": credentials_id, "resource": resource_id})
			return aiohttp.web.HTTPForbidden()
		try:
			await self.ResourceService.delete(resource_id, hard_delete=hard_delete)
		except exceptions.NotEditableError as e:
			return e.json_response(request)
		return asab.web.rest.json_response(request, {"result": "OK"})
