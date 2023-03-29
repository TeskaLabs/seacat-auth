import logging

import aiohttp
import aiohttp.web

import asab
import asab.web.rest
import asab.web.webcrypto

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

		self.SessionService = app.get_service('seacatauth.SessionService')
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.AuditService = app.get_service('seacatauth.AuditService')

		web_app = app.WebContainer.WebApp

		web_app.router.add_get('/credentials', self.list_credentials)
		web_app.router.add_put('/idents', self.get_idents_from_ids)
		web_app.router.add_put('/usernames', self.get_idents_from_ids)  # TODO: Back compat. Remove once UI adapts to the new endpoint.
		web_app.router.add_get('/locate', self.locate_credentials)
		web_app.router.add_get('/credentials/{credentials_id}', self.get_credentials)

		web_app.router.add_post('/credentials/{provider}', self.create_credentials)
		web_app.router.add_put('/credentials/{credentials_id}', self.update_credentials)
		web_app.router.add_delete('/credentials/{credentials_id}', self.delete_credentials)

		web_app.router.add_put('/public/credentials', self.update_my_credentials)

		# Providers
		web_app.router.add_get('/provider/{provider_id}', self.get_provider_info)
		web_app.router.add_get('/providers', self.list_providers)
		web_app.router.add_get('/public/provider', self.get_my_provider_info)
		web_app.router.add_put('/enforce-factors/{credentials_id}', self.enforce_factors)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_put('/public/credentials', self.update_my_credentials)
		web_app_public.router.add_get('/public/provider', self.get_my_provider_info)


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


	async def list_credentials(self, request):
		"""
		List credentials

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
		-	name: m
			in: query
			required: false
			description:
				Filter mode.

				- In the `default` mode, the request filters for credentials whose attributes contain
				the *filter string*. The actual attributes searched depend on the capabilities of the respective
				credential provider.

				- In the `tenant` mode, the request filters for credentials assigned to the tenant that exactly
				matches the *filter string*.

				- In the `role` mode, the request filters for credentials with the role that exactly
				matches the *filter string*.
			schema:
				type: string
				enum: ["tenant", "role", "default"]
				default: default
		"""
		page = int(request.query.get('p', 1)) - 1
		limit = int(request.query.get('i', 10))

		# Filter mode switches between `default` (username) string filter, `role` match and `tenant` match
		mode = request.query.get("m", "default")
		filtr = request.query.get("f", "")
		if len(filtr) == 0:
			filtr = None

		# Filtering based on IDs obtained form another collection
		if mode in frozenset(["role", "tenant"]):
			if filtr is None:
				L.error("No filter string specified.", struct_data={"mode": mode})
				raise aiohttp.web.HTTPBadRequest()

			# These filters require access dedicated resource
			rbac_svc = self.CredentialsService.App.get_service("seacatauth.RBACService")

			if mode == "role":
				# Check if the user has admin access to the role's tenant
				tenant = filtr.split("/")[0]
				if not rbac_svc.has_resource_access(
					request.Session.Authorization.Authz, tenant, ["seacat:role:access"]
				):
					return asab.web.rest.json_response(request, {
						"result": "NOT-AUTHORIZED"
					})
				role_svc = self.CredentialsService.App.get_service("seacatauth.RoleService")
				assignments = await role_svc.list_role_assignments(role_id=filtr, page=page, limit=limit)

			elif mode == "tenant":
				# Check if the user has admin access to the requested tenant
				tenant = filtr
				if not rbac_svc.has_resource_access(
					request.Session.Authorization.Authz, tenant, ["seacat:tenant:access"]
				):
					return asab.web.rest.json_response(request, {
						"result": "NOT-AUTHORIZED"
					})
				tenant_svc = self.CredentialsService.App.get_service("seacatauth.TenantService")
				provider = tenant_svc.get_provider()
				assignments = await provider.list_tenant_assignments(tenant, page, limit)

			else:
				raise ValueError("Unknown mode: {}".format(mode))

			if assignments["count"] == 0:
				return asab.web.rest.json_response(request, {
					"result": "OK",
					"count": 0,
					"data": []
				})

			credentials = []
			total_count = assignments["count"]

			# Sort the ids by their respective provider
			for assignment in assignments["data"]:
				cid = assignment["c"]
				_, provider_id, _ = cid.split(":", 2)
				provider = self.CredentialsService.CredentialProviders[provider_id]
				try:
					credentials.append(await provider.get(cid))
				except KeyError:
					L.warning("Found an assignment of nonexisting credentials", struct_data={
						"cid": cid,
						"assigned_to": filtr,
					})

		# Substring based filtering
		elif mode in frozenset(["", "default"]):
			stack = []
			total_count = 0  # If -1, then total count cannot be determined
			for provider in self.CredentialsService.CredentialProviders.values():
				try:
					count = await provider.count(filtr=filtr)
				except Exception as e:
					L.exception("Exception when getting count from a credentials provider: {}".format(e))
					continue

				stack.append((count, provider))
				if count >= 0 and total_count >= 0:
					total_count += count
				else:
					total_count = -1

			# Scroll to first relevant provider
			offset = page * limit
			credentials = []

			for count, provider in stack:
				if count >= 0:
					if offset > count:
						# The offset is beyond the count of the provider, so let's skip to the next one
						offset -= count
						continue

					async for credobj in provider.iterate(offset=offset, limit=limit, filtr=filtr):
						credentials.append(credobj)
						limit -= 1

					if limit <= 0:
						#  We are done here ...
						break

					# Continue to the beginning of the next provider (zero offset)
					offset = 0

				else:
					# TODO: Uncountable branch
					L.error("Not implemented: Uncountable branch.", struct_data={"provider_id": provider.ProviderID})
					continue

		else:
			L.error("Unsupported filter mode", struct_data={"mode": mode})
			raise aiohttp.web.HTTPBadRequest()

		return asab.web.rest.json_response(request, {
			"result": "OK",
			"data": credentials,
			"count": total_count,
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
		Get requested credentials' metadata
		"""
		credentials_id = request.match_info["credentials_id"]
		_, provider_id, _ = credentials_id.split(':', 2)
		provider = self.CredentialsService.CredentialProviders[provider_id]

		credentials = await provider.get(request.match_info["credentials_id"])

		credentials['_ll'] = await self.AuditService.get_last_logins(credentials_id)

		return asab.web.rest.json_response(request, credentials)


	@asab.web.rest.json_schema_handler(CREATE_CREDENTIALS)
	@access_control()
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
			await crd_svc.init_password_change(credentials_id, is_new_user=True)

		return asab.web.rest.json_response(request, {
			"status": "OK",
			"_id": credentials_id,
			"_type": provider.Type,
			"_provider_id": provider.ProviderID
		})


	@asab.web.rest.json_schema_handler(UPDATE_CREDENTIALS)
	@access_control("authz:superuser")
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


	@access_control("authz:superuser")
	async def delete_credentials(self, request, *, credentials_id):
		"""
		Delete credentials
		"""
		agent_cid = credentials_id  # Who called the request
		credentials_id = request.match_info["credentials_id"]  # Who will be deleted
		result = await self.CredentialsService.delete_credentials(credentials_id, agent_cid)
		return asab.web.rest.json_response(request, {"result": result})
