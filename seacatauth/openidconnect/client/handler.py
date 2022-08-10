import logging
import re

import asab
import asab.web.rest
import asab.exceptions

from ...decorators import access_control
from .service import CLIENT_METADATA_SCHEMA

#

L = logging.getLogger(__name__)

#


class ClientHandler(object):
	def __init__(self, app, client_svc):
		self.ClientService = client_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/client", self.list)
		web_app.router.add_get("/client/{client_id}", self.get)
		web_app.router.add_post("/client", self.register)
		web_app.router.add_post("/client/{client_id}/reset_secret", self.reset_secret)
		web_app.router.add_put("/client/{client_id}", self.update)
		web_app.router.add_delete("/client/{client_id}", self.delete)


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
				"_id": re.compile("^{}".format(re.escape(query_filter)))}

		data = []
		async for client in self.ClientService.iterate(page, limit, query_filter):
			data.append(self._rest_normalize(client))

		count = await self.ClientService.count(query_filter)

		return asab.web.rest.json_response(request, {
			"data": data,
			"count": count,
		})


	@access_control("authz:superuser")
	async def get(self, request):
		client_id = request.match_info["client_id"]
		result = self._rest_normalize(
			await self.ClientService.get(client_id),
			include_client_secret=True)
		return asab.web.rest.json_response(
			request, result
		)


	@asab.web.rest.json_schema_handler(CLIENT_METADATA_SCHEMA)
	@access_control("authz:superuser")
	async def register(self, request, *, json_data):
		data = await self.ClientService.register(**json_data)
		return asab.web.rest.json_response(request, data=data)


	@asab.web.rest.json_schema_handler(CLIENT_METADATA_SCHEMA)
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
		response = await self.ClientService.reset_secret(client_id)
		return asab.web.rest.json_response(
			request,
			data=response,
		)


	@access_control("authz:superuser")
	async def delete(self, request):
		client_id = request.match_info["client_id"]
		await self.ClientService.delete(client_id)
		return asab.web.rest.json_response(
			request,
			data={"result": "OK"},
		)


	def _rest_normalize(self, client: dict, include_client_secret: bool = False):
		rest_data = {
			k: v
			for k, v in client.items()
			if not k.startswith("__")
		}
		rest_data["client_id"] = rest_data["_id"]
		rest_data["client_id_issued_at"] = int(rest_data["_c"].timestamp())
		if include_client_secret and "__client_secret" in client:
			rest_data["client_secret"] = client["__client_secret"]
			if "client_secret_expires_at" in rest_data:
				rest_data["client_secret_expires_at"] = int(rest_data["client_secret_expires_at"].timestamp())
		return rest_data
