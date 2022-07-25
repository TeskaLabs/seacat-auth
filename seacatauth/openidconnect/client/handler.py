import logging
import re

import asab
import asab.web.rest

from seacatauth.decorators import access_control

#

L = logging.getLogger(__name__)

#


class ClientHandler(object):
	def __init__(self, app, client_svc):
		self.ClientService = client_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/client", self.list)
		web_app.router.add_get("/client/{client_id}", self.get)
		web_app.router.add_post("/client/{client_id}", self.create)
		web_app.router.add_post("/client/{client_id}/reset_secret", self.reset_secret)
		web_app.router.add_put("/client/{client_id}", self.update)


	@access_control("authz:superuser")
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

		data = await self.ClientService.list(page, limit, query_filter)
		return asab.web.rest.json_response(request, data)


	@access_control("authz:superuser")
	async def get(self, request):
		client_id = request.match_info["client_id"]
		result = await self.ClientService.get(client_id)
		return asab.web.rest.json_response(
			request, result
		)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["base_url"],
		"additionalProperties": False,
		"properties": {
			"description": {
				"type": "string",
			},
			"base_url": {
				"type": "string",
			},
			"scope": {
				"type": "array",
			},
		}
	})
	@access_control("authz:superuser")
	async def create(self, request, *, json_data):
		client_id = request.match_info["client_id"]

		data = await self.ClientService.create(client_id, **json_data)

		return asab.web.rest.json_response(request, data=data)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"additionalProperties": False,
		"properties": {
			"description": {
				"type": "string",
			},
			"base_url": {
				"type": "string",
			},
			"scope": {
				"type": "array",
			},
		}
	})
	@access_control("authz:superuser")
	async def update(self, request, *, json_data):
		client_id = request.match_info["client_id"]
		await self.ClientService.update(client_id, **json_data)
		return asab.web.rest.json_response(
			request,
			data={"result": "OK"},
		)


	@access_control("authz:superuser")
	async def reset_secret(self, request):
		client_id = request.match_info["client_id"]
		client_secret = await self.ClientService.reset_secret(client_id)
		return asab.web.rest.json_response(
			request,
			data={"client_secret": client_secret},
		)
