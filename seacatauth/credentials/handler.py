import logging

import asab
import asab.web.rest
import asab.web.webcrypto
import asab.exceptions
import asab.utils

from .. import exceptions, generic
from ..decorators import access_control
from .schemas import (
	CREATE_CREDENTIALS,
	UPDATE_CREDENTIALS,
	UPDATE_MY_CREDENTIALS,
)

#

L = logging.getLogger(__name__)

#


class CredentialsHandler(object):
	"""
	Credential management

	---
	tags: ["Credential management"]
	"""

	def __init__(self, app, credentials_svc):
		self.CredentialsService = credentials_svc

		self.SessionService = app.get_service("seacatauth.SessionService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.LastActivityService = app.get_service("seacatauth.LastActivityService")

		web_app = app.WebContainer.WebApp

		web_app.router.add_get("/credentials", self.list_credentials)
		web_app.router.add_put("/idents", self.get_idents_from_ids)
		web_app.router.add_put("/usernames", self.get_idents_from_ids)  # TODO: Back compat. Remove once UI adapts to the new endpoint.
		web_app.router.add_get("/locate", self.locate_credentials)
		web_app.router.add_get("/credentials/{credentials_id}", self.get_credentials)
		web_app.router.add_get("/last_login/{credentials_id}", self.get_last_login_data)

		web_app.router.add_post("/credentials/{provider}", self.create_credentials)
		web_app.router.add_put("/credentials/{credentials_id}", self.update_credentials)
		web_app.router.add_delete("/credentials/{credentials_id}", self.delete_credentials)

		web_app.router.add_get("/provider/{provider_id}", self.get_provider_info)
		web_app.router.add_get("/providers", self.list_providers)
		web_app.router.add_put("/enforce-factors/{credentials_id}", self.enforce_factors)

		web_app.router.add_get("/account/provider", self.get_my_provider_info)
		web_app.router.add_put("/account/credentials", self.update_my_credentials)
		web_app.router.add_get("/account/last-login", self.get_my_last_login_data)

		# Back-compat; To be removed in next major version
		# >>>
		web_app.router.add_get("/public/provider", self.get_my_provider_info)
		web_app.router.add_put("/public/credentials", self.update_my_credentials)
		web_app.router.add_get("/public/last_login", self.get_my_last_login_data)

		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_put("/public/credentials", self.update_my_credentials)
		web_app_public.router.add_get("/public/provider", self.get_my_provider_info)
		web_app_public.router.add_get("/public/last_login", self.get_my_last_login_data)
		# <<<


	async def list_providers(self, request):
		"""
		Get credential providers and their metadata
		"""
		providers = {}
		for provider_id in self.CredentialsService.CredentialProviders:
			providers[provider_id] = self.CredentialsService.get_provider_info(provider_id)
		return asab.web.rest.json_response(request, providers)


	async def get_provider_info(self, request):
		"""
		Get the metadata of the requested credential provider.
		"""
		provider_id = request.match_info["provider_id"]
		data = self.CredentialsService.get_provider_info(provider_id)
		response = {
			"result": "OK",  # TODO: Redundant field
			**data,
		}
		return asab.web.rest.json_response(request, response)


	@access_control()
	async def get_my_provider_info(self, request, *, credentials_id):
		"""
		Get the metadata of the current user's credential provider.
		"""
		provider = self.CredentialsService.get_provider(credentials_id)
		data = self.CredentialsService.get_provider_info(provider.ProviderID)
		response = {
			"result": "OK",
			"data": data,
		}
		return asab.web.rest.json_response(request, response)


	async def get_last_login_data(self, request):
		"""
		Get the credentials' last successful/failed login data.
		"""
		credentials_id = request.match_info["credentials_id"]
		data = await self.LastActivityService.get_last_logins(credentials_id)
		return asab.web.rest.json_response(request, data)


	@access_control()
	async def get_my_last_login_data(self, request, *, credentials_id):
		"""
		Get the current user's last successful/failed login data.
		"""
		if request.Session.is_anonymous():
			raise asab.exceptions.AccessDeniedError()
		data = await self.LastActivityService.get_last_logins(credentials_id)
		return asab.web.rest.json_response(request, data)


	async def locate_credentials(self, request):
		"""
		Return the IDs of credentials that match the specified ident.

		---
		parameters:
		-	name: ident
			in: query
			required: true
			description:
				Credential identifier. It may be email address, username, phone number etc., the exact supported
				attributes depend on the capabilities and the configuration of the credential providers.
			schema:
				type: string
		-	name: stop_at_first
			in: query
			required: false
			description: Whether to return only the first matched credentials' ID.
			schema:
				type: boolean
		"""
		ident = request.query.get("ident")
		stop_at_first = request.query.get("stop_at_first", "no").lower() in frozenset(["yes", "true", "1", "y"])
		credentials_ids = await self.CredentialsService.locate(ident, stop_at_first=stop_at_first)
		return asab.web.rest.json_response(request, {"credentials_ids": credentials_ids})


	@access_control()
	async def list_credentials(self, request):
		"""
		List credentials that are members of currently authorized tenant

		---
		parameters:
		-	name: p
			in: query
			description: Page number
			schema: {"type": "integer"}
		-	name: i
			in: query
			description: Items per page
			schema: {"type": "integer"}
		-	name: f
			in: query
			description: Filter by username or email
			schema: {"type": "string"}
		-	name: atenant
			in: query
			required: false
			description: Filter by tenant
			schema: {"type": "string"}
		-	name: arole
			in: query
			required: false
			description: Filter by role
			schema: {"type": "string"}
		-	name: global
			in: query
			required: false
			description:
			schema: {"type": "boolean"}
		"""
		search = generic.SearchParams(request.query)

		# BACK-COMPAT: Convert the old "mode" search to advanced filters
		mode = request.query.get("m", "default")
		if mode == "role":
			search.AdvancedFilter["role"] = request.query.get("f")
		elif mode == "tenant":
			search.AdvancedFilter["tenant"] = request.query.get("f")
		elif mode == "default":
			search.SimpleFilter = request.query.get("f")

		if len(search.AdvancedFilter) > 1:
			raise asab.exceptions.ValidationError("No more than one advanced filter at a time is supported.")

		try_global_search = asab.utils.string_to_boolean(request.query.get("global", "false"))

		result = await self.CredentialsService.list(request.Session, search, try_global_search)

		return asab.web.rest.json_response(request, {
			"result": "OK",
			"data": result["data"],
			"count": result["count"],
		})


	@asab.web.rest.json_schema_handler({
		"type": "array",
		"items": {
			"type": "string"
		}
	})
	async def get_idents_from_ids(self, request, *, json_data):
		"""
		Get human-intelligible identifiers for a list of credential IDs
		"""
		result_data = {}
		failed_ids = []
		for cred_id in json_data:
			try:
				cred_obj = await self.CredentialsService.get(cred_id)
			except KeyError:
				failed_ids.append(cred_id)
				continue
			ident = cred_obj.get("username") \
				or cred_obj.get("email") \
				or cred_obj.get("phone") \
				or cred_id
			result_data[cred_id] = ident

		if len(failed_ids) > 0:
			L.warning("Credentials not found", struct_data={
				"cids": failed_ids
			})
		return asab.web.rest.json_response(request, {
			"result": "OK",
			"data": result_data
		})

	async def get_credentials(self, request):
		"""
		Get requested credentials' detail

		---
		parameters:
		-	name: last_login
			in: query
			description: Whether to include the last successful and failed login data
			required: false
			schema:
				type: boolean
				default: no
		"""
		credentials_id = request.match_info["credentials_id"]

		# Check authorization:
		#   the requester must be authorized for any of the tenants that the requested is a member of
		if not request.Session.is_superuser():
			for tenant in request.Session.Authorization.Authz:
				if tenant != "*":
					continue
				if self.TenantService.has_tenant_assigned(credentials_id, tenant):
					break
				else:
					continue
			else:
				# No tenant in common
				return asab.web.rest.json_response(request, {"result": "FORBIDDEN"}, code=403)

		_, provider_id, _ = credentials_id.split(':', 2)
		provider = self.CredentialsService.CredentialProviders[provider_id]

		credentials = await provider.get(request.match_info["credentials_id"])

		if asab.config.utils.string_to_boolean(request.query.get("last_login", "no")):
			credentials["_ll"] = await self.LastActivityService.get_last_logins(credentials_id)

		return asab.web.rest.json_response(request, credentials)


	@asab.web.rest.json_schema_handler(CREATE_CREDENTIALS)
	@access_control("seacat:credentials:edit")
	async def create_credentials(self, request, *, json_data):
		"""
		Create new credentials
		"""
		password_link = json_data.pop("passwordlink", False)

		provider_id = request.match_info["provider"]
		provider = self.CredentialsService.CredentialProviders[provider_id]

		# Create credentials
		result = await self.CredentialsService.create_credentials(provider_id, json_data, request.Session)

		if result["status"] != "OK":
			return asab.web.rest.json_response(request, result, status=400)

		credentials_id = result["credentials_id"]

		if password_link:
			# TODO: Separate password creation from password reset
			crd_svc = self.SessionService.App.get_service("seacatauth.ChangePasswordService")
			try:
				await crd_svc.init_password_change(credentials_id, is_new_user=True)
			except exceptions.CommunicationError:
				L.error("Password reset failed: Failed to send password change link", struct_data={
					"cid": credentials_id})

		return asab.web.rest.json_response(request, {
			"status": "OK",
			"_id": credentials_id,
			"_type": provider.Type,
			"_provider_id": provider.ProviderID
		})


	@asab.web.rest.json_schema_handler(UPDATE_CREDENTIALS)
	@access_control("seacat:credentials:edit")
	async def update_credentials(self, request, *, json_data):
		"""
		Update credentials
		"""
		credentials_id = request.match_info["credentials_id"]

		# Update credentials
		result = await self.CredentialsService.update_credentials(credentials_id, json_data, request.Session)

		result["result"] = result["status"]  # TODO: Unify response format

		if result["result"] != "OK":
			return asab.web.rest.json_response(request, result, status=400)

		return asab.web.rest.json_response(request, result)


	@asab.web.rest.json_schema_handler(UPDATE_MY_CREDENTIALS)
	@access_control()
	async def update_my_credentials(self, request, *, json_data, credentials_id):
		"""
		Update the current user's own credentials
		"""
		result = await self.CredentialsService.update_credentials(
			credentials_id,
			json_data,
			request.Session,
		)

		result["result"] = result["status"]  # TODO: Unify response format

		if result["status"] != "OK":
			return asab.web.rest.json_response(request, result, status=400)

		return asab.web.rest.json_response(request, result)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"additionalProperties": False,
		"required": ["factors"],
		"properties": {
			"factors": {
				"type": "array",
				"description": "Factors to enforce/reset"
			}
		}
	})
	@access_control("seacat:credentials:edit")
	async def enforce_factors(self, request, *, json_data):
		"""
		Specify authentication factors to be enforced from the user
		"""
		credentials_id = request.match_info["credentials_id"]
		provider = self.CredentialsService.get_provider(credentials_id)

		enforce_factors = json_data.get("factors")

		# TODO: Implement and use LoginFactor.can_be_enforced() method
		for factor in enforce_factors:
			if factor not in frozenset(["totp", "smscode", "password"]):
				raise ValueError("Login factor cannot be enforced", {"factor": factor})

		result = await provider.update(credentials_id, {
			"enforce_factors": enforce_factors
		})

		return asab.web.rest.json_response(request, {"result": result})


	@access_control("seacat:credentials:edit")
	async def delete_credentials(self, request, *, credentials_id):
		"""
		Delete credentials
		"""
		agent_cid = credentials_id  # Who called the request
		credentials_id = request.match_info["credentials_id"]  # Who will be deleted
		result = await self.CredentialsService.delete_credentials(credentials_id, agent_cid)
		return asab.web.rest.json_response(request, {"result": result})
