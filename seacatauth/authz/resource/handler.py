import logging
import re

import aiohttp.web
import asab
import asab.web.rest

from seacatauth.decorators import access_control

#

L = logging.getLogger(__name__)

#


class ResourceHandler(object):
	"""
	Manage resources

	---
	tags: ["Manage resources"]
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
		"""
		page = int(request.query.get("p", 1)) - 1
		limit = request.query.get("i", None)
		if limit is not None:
			limit = int(limit)

		# Filter by ID.startswith()
		query_filter = {}
		if "f" in request.query:
			query_filter["_id"] = re.compile(
				"^{}".format(re.escape(request.query["f"])))

		# Do not include soft-deleted resources unless requested
		if request.query.get("include_deleted") != "true":
			query_filter["deleted"] = {"$in": [None, False]}

		resources = await self.ResourceService.list(page, limit, query_filter)
		return asab.web.rest.json_response(request, resources)


	async def get(self, request):
		"""
		Get resource detail
		"""
		resource_id = request.match_info["resource_id"]
		result = await self.ResourceService.get(resource_id)
		result["result"] = "OK"
		return asab.web.rest.json_response(
			request, result
		)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"additionalProperties": False,
		"properties": {
			"description": {"type": "string"}}
	})
	@access_control("authz:superuser")
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
	@access_control("authz:superuser")
	async def update(self, request, *, json_data):
		"""
		Update resource description or rename resource
		"""
		resource_id = request.match_info["resource_id"]
		if "description" in json_data:
			await self.ResourceService.update(resource_id, json_data["description"])
		if "name" in json_data:
			await self.ResourceService.rename(resource_id, json_data["name"])

		return asab.web.rest.json_response(request, {"result": "OK"})


	@access_control("authz:superuser")
	async def delete(self, request):
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
			raise aiohttp.web.HTTPForbidden()
		await self.ResourceService.delete(resource_id, hard_delete=hard_delete)
		return asab.web.rest.json_response(request, {"result": "OK"})
