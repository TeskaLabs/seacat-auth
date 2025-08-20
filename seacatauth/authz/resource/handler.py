import logging
import re

import asab
import asab.contextvars
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.exceptions
import asab.utils

from ... import exceptions, generic
from ...models.const import ResourceId
from . import schema


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


	@asab.web.tenant.allow_no_tenant
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
		-	name: a_id!
			in: query
			description: Resource IDs to exclude from the results (comma-separated).
			required: false
			explode: false
			schema:
				type: array
		-	name: a_id
			in: query
			description: Resource IDs to search (comma-separated).
			required: false
			explode: false
			schema:
				type: array
		-	name: acontext
			in: query
			description:
				Context in which the resource can be used. If set to "tenant", only resources that are not
				global-only are returned. Defaults to "global", returning all resources.
			required: false
			schema:
				type: string
				enum: ["tenant", "global"]
		-	name: aauthorized
			in: query
			description:
				Filter to authorized or unauthorized resources. If set to "true", only resources that the user is
				authorized to access are returned.
			required: false
			schema:
				type: boolean
		-	name: adeleted
			in: query
			description:
				Filter to active or soft-deleted resources. If set to "true", only deleted resources are listed.
				Defaults to "false", listing only active resources.
			required: false
			schema:
				type: boolean
		"""
		page = int(request.query.get("p", 1)) - 1
		limit = request.query.get("i", None)
		if limit is not None:
			limit = int(limit)

		query_filter = _build_resource_filter(request.query)
		resources = await self.ResourceService.list(page, limit, query_filter)
		return asab.web.rest.json_response(request, resources)


	@asab.web.tenant.allow_no_tenant
	async def get(self, request):
		"""
		Get resource detail
		"""
		resource_id = request.match_info["resource_id"]
		result = await self.ResourceService.get(resource_id)
		return asab.web.rest.json_response(
			request, result
		)


	@asab.web.rest.json_schema_handler(schema.CREATE_OR_UNDELETE_RESOURCE)
	@asab.web.auth.require(ResourceId.RESOURCE_EDIT)
	@asab.web.tenant.allow_no_tenant
	async def create_or_undelete(self, request, *, json_data):
		"""
		Create a new resource or undelete a soft-deleted resource
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
			await self.ResourceService.create(resource_id, **json_data)
		return asab.web.rest.json_response(request, {"result": "OK"})


	@asab.web.rest.json_schema_handler(schema.UPDATE_RESOURCE)
	@asab.web.auth.require(ResourceId.RESOURCE_EDIT)
	@asab.web.tenant.allow_no_tenant
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


	@asab.web.auth.require(ResourceId.RESOURCE_EDIT)
	@asab.web.tenant.allow_no_tenant
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
				Hard-deleting requires superuser privileges.
			required: false
			schema:
				type: boolean
				enum: ["true"]
		"""
		authz = asab.contextvars.Authz.get()
		resource_id = request.match_info["resource_id"]

		hard_delete = request.query.get("hard_delete") == "true"
		if hard_delete:
			authz.require_superuser_access()

		try:
			await self.ResourceService.delete(resource_id, hard_delete=hard_delete)
		except exceptions.NotEditableError as e:
			return e.json_response(request)
		return asab.web.rest.json_response(request, {"result": "OK"})


def _build_resource_filter(query: dict = None) -> dict | bool:
	"""
	Build a filter for resources based on the current tenant and authorization context.
	"""
	query_filter = {}

	# Search in resource ID
	name_filter = query.get("f")
	if name_filter:
		generic.update_mongodb_filter(query_filter, "_id", {"$regex": re.escape(name_filter)})

	if "adeleted" in query:
		deleted = asab.utils.string_to_boolean(query.get("adeleted"))
	else:
		# Do not include deleted items by default
		deleted = {"$in": [False, None]}
	generic.update_mongodb_filter(query_filter, "deleted", deleted)

	if "acontext" in query:
		context = query.get("acontext")
		if context == "tenant":
			# Exclude global-only resources
			generic.update_mongodb_filter(query_filter, "global_only.$ne", True)
		elif context == "global":
			# Include all resources
			pass
		else:
			# Unknown context, return empty result
			return False

	if "aauthorized" in query:
		authz = asab.contextvars.Authz.get()

		if asab.utils.string_to_boolean(query["aauthorized"]) is True:
			# Filter to authorized resources only
			if authz.has_superuser_access():
				pass
			else:
				generic.update_mongodb_filter(query_filter, "_id.$in", authz._resources())
		else:
			# Filter to unauthorized resources only
			if authz.has_superuser_access():
				# There is nothing to filter, superuser can see all resources
				return False
			else:
				generic.update_mongodb_filter(query_filter, "_id.$nin", authz._resources())

	exclude_ids = query.get("a_id!")
	if exclude_ids:
		generic.update_mongodb_filter(query_filter, "_id.$nin", exclude_ids.split(","))

	search_ids = query.get("a_id")
	if search_ids:
		generic.update_mongodb_filter(query_filter, "_id.$in", search_ids.split(","))

	return query_filter
