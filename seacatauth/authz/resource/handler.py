import logging
import re
from json import JSONDecodeError

import asab
import asab.web.rest
import asab.exceptions

from seacatauth.decorators import access_control

#

L = logging.getLogger(__name__)

#


class ResourceHandler(object):
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
		page = int(request.query.get("p", 1)) - 1
		limit = request.query.get("i", None)
		if limit is not None:
			limit = int(limit)

		# Filter by ID.startswith()
		query_filter = request.query.get("f", None)
		if query_filter is not None:
			query_filter = {
				"_id": re.compile("^{}".format(
					re.escape(query_filter)
				))
			}

		resources = await self.ResourceService.list(page, limit, query_filter)
		return asab.web.rest.json_response(request, resources)

	async def get(self, request):
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
			"description": {
				"type": "string",
			},
		}
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
		Update resource name or description
		"""
		resource_id = request.match_info["resource_id"]
		description = json_data["description"]
		data = await self.ResourceService.update_description(resource_id, description)
		status = 200 if data["result"] == "OK" else 400
		return asab.web.rest.json_response(
			request,
			status=status,
			data=data,
		)


	@access_control("authz:superuser")
	async def delete(self, request):
		"""
		Delete a resource. The resource is soft-deleted (suspended) by default,
		unless "hard_delete=true" is specified in query.
		"""
		resource_id = request.match_info["resource_id"]
		hard_delete = request.query.get("hard_delete") == "true"
		await self.ResourceService.delete(resource_id, hard_delete=hard_delete)
		return asab.web.rest.json_response(request, {"result": "OK"})
