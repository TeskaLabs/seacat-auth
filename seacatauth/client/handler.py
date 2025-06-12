import logging
import asab
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.exceptions

from .. import generic, exceptions
from ..models.const import ResourceId
from .service import is_client_confidential
from . import schema


L = logging.getLogger(__name__)


class ClientHandler(object):
	"""
	Client management

	---
	tags: ["Clients (Applications)"]
	"""
	def __init__(self, app, client_svc):
		self.ClientService = client_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/admin/client", self.list_clients)
		web_app.router.add_get("/admin/client/features", self.client_features)
		web_app.router.add_get("/admin/client/{client_id}", self.get_client)
		web_app.router.add_post("/admin/client", self.register_client)
		web_app.router.add_put("/admin/client/{client_id}", self.update_client)
		web_app.router.add_delete("/admin/client/{client_id}", self.delete_client)
		web_app.router.add_post("/admin/client/{client_id}/reset_secret", self.reset_secret)

		# Client tokens
		web_app.router.add_post("/admin/client/{client_id}/token", self.issue_client_token)
		web_app.router.add_get("/admin/client/{client_id}/token", self.list_client_tokens)
		web_app.router.add_delete("/admin/client/{client_id}/token/{token_id}", self.revoke_client_token)
		web_app.router.add_delete("/admin/client/{client_id}/token", self.revoke_all_client_tokens)

		# DEPRECATED, remove after 2026-01-01
		# >>>
		web_app.router.add_get("/client", self.list_clients)
		web_app.router.add_get("/client/features", self.client_features)
		web_app.router.add_get("/client/{client_id}", self.get_client)
		web_app.router.add_post("/client", self.register_client)
		web_app.router.add_put("/client/{client_id}", self.update_client)
		web_app.router.add_delete("/client/{client_id}", self.delete_client)
		web_app.router.add_post("/client/{client_id}/reset_secret", self.reset_secret)
		web_app.router.add_post("/client/{client_id}/token", self.issue_client_token)
		web_app.router.add_get("/client/{client_id}/token", self.list_client_tokens)
		web_app.router.add_delete("/client/{client_id}/token/{token_id}", self.revoke_client_token)
		web_app.router.add_delete("/client/{client_id}/token", self.revoke_all_client_tokens)
		# <<<


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.CLIENT_ACCESS)
	async def list_clients(self, request):
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
		search = generic.SearchParams(request.query, sort_by_default=[("client_name", 1)])

		data = []
		async for client in self.ClientService.iterate_clients(
			search.Page, search.ItemsPerPage, search.SimpleFilter, sort_by=search.SortBy
		):
			data.append(self._rest_normalize(client))

		count = await self.ClientService.count_clients(search.SimpleFilter)

		return asab.web.rest.json_response(request, {
			"data": data,
			"count": count,
		})


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.CLIENT_ACCESS)
	async def get_client(self, request):
		"""
		Get client by client_id
		"""
		client_id = request.match_info["client_id"]
		result = self._rest_normalize(await self.ClientService.get_client(client_id))
		return asab.web.rest.json_response(request, result)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.CLIENT_ACCESS)
	async def client_features(self, request):
		"""
		Get schema of supported client metadata

		https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
		"""
		result = {
			"metadata_schema": schema.REGISTER_CLIENT,
			"templates": schema.CLIENT_TEMPLATES,
		}
		return asab.web.rest.json_response(
			request, result
		)


	@asab.web.rest.json_schema_handler(schema.REGISTER_CLIENT)
	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.CLIENT_EDIT)
	async def register_client(self, request, *, json_data):
		"""
		Register a new client

		https://openid.net/specs/openid-connect-registration-1_0.html
		"""
		if "preferred_client_id" in json_data:
			if not self.ClientService._AllowCustomClientID:
				raise asab.exceptions.ValidationError("Specifying custom client_id is not allowed.")
			json_data["_custom_client_id"] = json_data.pop("preferred_client_id")
		client_id = await self.ClientService.create_client(**json_data)
		client = await self.ClientService.get_client(client_id)
		response_data = self._rest_normalize(client)

		if is_client_confidential(client):
			# Set a secret for confidential client
			client_secret, client_secret_expires_at = await self.ClientService.reset_secret(client_id)
			response_data["client_secret"] = client_secret
			if client_secret_expires_at:
				response_data["client_secret_expires_at"] = client_secret_expires_at

		return asab.web.rest.json_response(request, data=response_data)


	@asab.web.rest.json_schema_handler(schema.UPDATE_CLIENT)
	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.CLIENT_EDIT)
	async def update_client(self, request, *, json_data):
		"""
		Edit an existing client

		https://openid.net/specs/openid-connect-registration-1_0.html
		"""
		client_id = request.match_info["client_id"]
		if "preferred_client_id" in json_data:
			raise asab.exceptions.ValidationError("Cannot update attribute 'preferred_client_id'.")
		try:
			await self.ClientService.update_client(client_id, **json_data)
		except exceptions.NotEditableError as e:
			return e.json_response(request)
		return asab.web.rest.json_response(
			request,
			data={"result": "OK"},
		)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.CLIENT_EDIT)
	async def reset_secret(self, request):
		"""
		Reset client secret
		"""
		client_id = request.match_info["client_id"]
		try:
			client_secret, client_secret_expires_at = await self.ClientService.reset_secret(client_id)
		except exceptions.NotEditableError as e:
			return e.json_response(request)
		response_data = {"client_secret": client_secret}
		if client_secret_expires_at:
			response_data["client_secret_expires_at"] = client_secret_expires_at
		return asab.web.rest.json_response(
			request,
			data=response_data,
		)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.CLIENT_EDIT)
	async def delete_client(self, request):
		"""
		Delete a client
		"""
		client_id = request.match_info["client_id"]
		try:
			await self.ClientService.delete_client(client_id)
		except exceptions.NotEditableError as e:
			return e.json_response(request)
		return asab.web.rest.json_response(
			request,
			data={"result": "OK"},
		)


	@asab.web.tenant.allow_no_tenant
	@asab.web.rest.json_schema_handler(schema.ISSUE_TOKEN)
	@asab.web.auth.require(ResourceId.CLIENT_APIKEY_MANAGE)
	async def issue_client_token(self, request, *, json_data):
		"""
		Issue a new access token (API key) for a client
		"""
		client_id = request.match_info["client_id"]

		if "exp" in json_data:
			expires_at = generic.datetime_from_relative_or_absolute_timestring(json_data["exp"])
		else:
			expires_at = None

		try:
			token_response = await self.ClientService.issue_token(
				client_id,
				expires_at=expires_at,
				tenant=json_data.get("tenant"),
				label=json_data.get("label"),
			)
		except exceptions.TenantAccessDeniedError:
			return asab.web.rest.json_response(
				request,
				status=403,
				data={"result": "ERROR", "tech_err": "Tenant access denied."}
			)
		except exceptions.ClientNotFoundError:
			return asab.web.rest.json_response(
				request,
				status=404,
				data={"result": "ERROR", "tech_err": "Client not found."}
			)
		except exceptions.OAuth2InvalidClient:
			return asab.web.rest.json_response(
				request,
				status=404,
				data={"result": "ERROR", "tech_err": "Client does not have SeaCat Auth credentials."}
			)
		return asab.web.rest.json_response(
			request,
			data=token_response,
		)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.CLIENT_APIKEY_MANAGE)
	async def list_client_tokens(self, request):
		"""
		List client's active access tokens (API keys)
		"""
		client_id = request.match_info["client_id"]
		# TODO: Pagination
		token_response = await self.ClientService.list_tokens(client_id)
		return asab.web.rest.json_response(
			request,
			data=token_response,
		)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.CLIENT_APIKEY_MANAGE)
	async def revoke_client_token(self, request):
		"""
		Revoke client access token (API key) by its ID
		"""
		client_id = request.match_info["client_id"]
		token_id = request.match_info["token_id"]
		try:
			await self.ClientService.revoke_token(client_id, token_id)
		except (
			exceptions.ClientNotFoundError,
			exceptions.CredentialsNotFoundError,
			exceptions.SessionNotFoundError
		):
			return asab.web.rest.json_response(
				request,
				status=404,
				data={"result": "ERROR", "tech_err": "Token not found."}
			)
		return asab.web.rest.json_response(request, {"result": "OK"})


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.CLIENT_APIKEY_MANAGE)
	async def revoke_all_client_tokens(self, request):
		"""
		Revoke all tokens for a client
		"""
		client_id = request.match_info["client_id"]
		try:
			await self.ClientService.revoke_all_tokens(client_id)
		except exceptions.ClientNotFoundError:
			return asab.web.rest.json_response(
				request,
				status=404,
				data={"result": "ERROR", "tech_err": "Client not found."}
			)
		return asab.web.rest.json_response(request, {"result": "OK"})


	def _rest_normalize(self, client: dict):
		rest_data = {
			k: v
			for k, v in client.items()
			if not k.startswith("__")
		}
		rest_data["client_id_issued_at"] = int(rest_data["_c"].timestamp())
		if "__client_secret" in client:
			rest_data["client_secret"] = True
			if "client_secret_expires_at" in rest_data:
				rest_data["client_secret_expires_at"] = int(rest_data["client_secret_expires_at"].timestamp())
		return rest_data
