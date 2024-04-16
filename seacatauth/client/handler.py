import logging

import asab
import asab.web.rest
import asab.exceptions

from seacatauth.decorators import access_control
from .service import REGISTER_CLIENT_SCHEMA, UPDATE_CLIENT_SCHEMA, CLIENT_TEMPLATES, is_client_confidential

#

L = logging.getLogger(__name__)

#


class ClientHandler(object):
	"""
	Client management

	---
	tags: ["Clients (Applications)"]
	"""
	def __init__(self, app, client_svc):
		self.ClientService = client_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/client", self.list)
		web_app.router.add_get("/client/features", self.features)
		web_app.router.add_get("/client/{client_id}", self.get)
		web_app.router.add_post("/client", self.register)
		web_app.router.add_post("/client/{client_id}/reset_secret", self.reset_secret)
		web_app.router.add_put("/client/{client_id}", self.update)
		web_app.router.add_delete("/client/{client_id}", self.delete)


	@access_control("seacat:client:access")
	async def list(self, request):
		"""
		List registered clients

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
		page = int(request.query.get("p", 1)) - 1
		limit = request.query.get("i", None)
		if limit is not None:
			limit = int(limit)

		# Filter by ID.startswith()
		query_filter = request.query.get("f")

		data = []
		async for client in self.ClientService.iterate(page, limit, query_filter):
			data.append(self._rest_normalize(client))

		count = await self.ClientService.count(query_filter)

		return asab.web.rest.json_response(request, {
			"data": data,
			"count": count,
		})


	@access_control("seacat:client:access")
	async def get(self, request):
		"""
		Get client by client_id
		"""
		client_id = request.match_info["client_id"]
		result = self._rest_normalize(await self.ClientService.get(client_id))
		return asab.web.rest.json_response(request, result)


	@access_control("seacat:client:access")
	async def features(self, request):
		"""
		Get schema of supported client metadata

		https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
		"""
		result = {
			"metadata_schema": REGISTER_CLIENT_SCHEMA,
			"templates": CLIENT_TEMPLATES,
		}
		return asab.web.rest.json_response(
			request, result
		)


	@asab.web.rest.json_schema_handler(REGISTER_CLIENT_SCHEMA)
	@access_control("seacat:client:edit")
	async def register(self, request, *, json_data):
		"""
		Register a new client

		https://openid.net/specs/openid-connect-registration-1_0.html
		"""
		if "preferred_client_id" in json_data:
			if not self.ClientService._AllowCustomClientID:
				raise asab.exceptions.ValidationError("Specifying custom client_id is not allowed.")
			json_data["_custom_client_id"] = json_data.pop("preferred_client_id")
		client_id = await self.ClientService.register(**json_data)
		client = await self.ClientService.get(client_id)
		response_data = self._rest_normalize(client)

		if is_client_confidential(client):
			# Set a secret for confidential client
			client_secret, client_secret_expires_at = await self.ClientService.reset_secret(client_id)
			response_data["client_secret"] = client_secret
			if client_secret_expires_at:
				response_data["client_secret_expires_at"] = client_secret_expires_at

		return asab.web.rest.json_response(request, data=response_data)


	@asab.web.rest.json_schema_handler(UPDATE_CLIENT_SCHEMA)
	@access_control("seacat:client:edit")
	async def update(self, request, *, json_data):
		"""
		Edit an existing client

		https://openid.net/specs/openid-connect-registration-1_0.html
		"""
		client_id = request.match_info["client_id"]
		if "preferred_client_id" in json_data:
			raise asab.exceptions.ValidationError("Cannot update attribute 'preferred_client_id'.")
		await self.ClientService.update(client_id, **json_data)
		return asab.web.rest.json_response(
			request,
			data={"result": "OK"},
		)


	@access_control("seacat:client:edit")
	async def reset_secret(self, request):
		"""
		Reset client secret
		"""
		client_id = request.match_info["client_id"]
		client_secret, client_secret_expires_at = await self.ClientService.reset_secret(client_id)
		response_data = {"client_secret": client_secret}
		if client_secret_expires_at:
			response_data["client_secret_expires_at"] = client_secret_expires_at
		return asab.web.rest.json_response(
			request,
			data=response_data,
		)


	@access_control("seacat:client:edit")
	async def delete(self, request):
		"""
		Delete a client
		"""
		client_id = request.match_info["client_id"]
		await self.ClientService.delete(client_id)
		return asab.web.rest.json_response(
			request,
			data={"result": "OK"},
		)


	def _rest_normalize(self, client: dict):
		cookie_service = self.ClientService.App.get_service("seacatauth.CookieService")

		rest_data = {
			k: v
			for k, v in client.items()
			if not k.startswith("__")
		}
		rest_data["client_id"] = rest_data["_id"]
		rest_data["client_id_issued_at"] = int(rest_data["_c"].timestamp())
		if "__client_secret" in client:
			rest_data["client_secret"] = True
			if "client_secret_expires_at" in rest_data:
				rest_data["client_secret_expires_at"] = int(rest_data["client_secret_expires_at"].timestamp())
		rest_data["cookie_name"] = cookie_service.get_cookie_name(rest_data["_id"])
		return rest_data
