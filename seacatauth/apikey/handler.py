import logging
import asab
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.exceptions

from .. import generic, exceptions
from ..models.const import ResourceId


L = logging.getLogger(__name__)


class ApiKeyHandler(object):
	"""
	API key management

	---
	tags: ["API key management"]
	"""
	def __init__(self, app, api_key_svc):
		self.App = app
		self.ApiKeyService = api_key_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/admin/apikey", self.list_api_keys)
		web_app.router.add_post("/admin/apikey", self.create_api_key)
		web_app.router.add_get("/admin/apikey/{key_id}", self.get_api_key)
		web_app.router.add_put("/admin/apikey/{key_id}", self.update_api_key)
		web_app.router.add_delete("/admin/apikey/{key_id}", self.delete_api_key)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.APIKEY_ACCESS)
	async def list_api_keys(self, request):
		"""
		List API keys

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
			description: Filter
			schema:
				type: string
		"""
		search = generic.SearchParams(request.query, sort_by_default=[("_c", 1)])

		data = []
		for api_key in (await self.ApiKeyService.iterate_api_keys(
			search.Page, search.ItemsPerPage,
		)):
			data.append(api_key)

		return asab.web.rest.json_response(request, {
			"data": data,
		})


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.APIKEY_ACCESS)
	async def get_api_key(self, request):
		result = await self.ApiKeyService.get_api_key(request.match_info["key_id"])
		return asab.web.rest.json_response(request, result)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["label", "resources"],
		"properties": {
			"label": {
				"type": "string", "description": "Human-readable label for the API key"
			},
			"exp": {
				"oneOf": [{"type": "string"}, {"type": "number"}],
				"description":
					"API key expiration time. The value can be either the number of seconds, "
					"a time-unit duration string such as '4 h' or '3 d' "
					"or an ISO 8601 datetime such as '2030-05-08' or '2030-05-08T23:41:54.000Z'.",
			},
			"tenant": {
				"type": ["string", "null"],
				"description": "Tenant scope to authorize. If not specified, the API key is tenantless.",
			},
			"resources": {
				"type": "array",
				"description": "Resources to authorize.",
				"items": {"type": "string"},
			},
		},
	})
	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.APIKEY_MANAGE)
	async def create_api_key(self, request, *, json_data):
		if "exp" in json_data:
			expires_at = generic.datetime_from_relative_or_absolute_timestring(json_data["exp"])
		else:
			expires_at = None
		result = await self.ApiKeyService.create_api_key(
			expires_at=expires_at,
			tenant=json_data.get("tenant"),
			resources=json_data.get("resources"),
			label=json_data.get("label"),
		)
		return asab.web.rest.json_response(request, result)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"properties": {
			"label": {
				"type": "string", "description": "Label for the API key"
			},
		},
	})
	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.APIKEY_MANAGE)
	async def update_api_key(self, request, *, json_data):
		await self.ApiKeyService.update_api_key(**json_data)
		return asab.web.rest.json_response(
			request,
			data={"result": "OK"},
		)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.APIKEY_MANAGE)
	async def delete_api_key(self, request):
		await self.ApiKeyService.delete_api_key(request.match_info["key_id"])
		return asab.web.rest.json_response(
			request,
			data={"result": "OK"},
		)
