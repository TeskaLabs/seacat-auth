import logging
import asab
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.exceptions
import asab.utils
import asab.contextvars

from .. import exceptions
from ..models.const import ResourceId
from . import schema


L = logging.getLogger(__name__)


class CredentialsHandler(object):
	"""
	Credential management

	---
	tags: ["Users and credentials"]
	"""

	def __init__(self, app, credentials_svc):
		self.App = app
		self.CredentialsService = credentials_svc

		self.SessionService = app.get_service("seacatauth.SessionService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.LastActivityService = app.get_service("seacatauth.LastActivityService")

		web_app = app.WebContainer.WebApp

		web_app.router.add_get("/admin/credentials-provider", self.list_providers)
		web_app.router.add_get("/admin/credentials-provider/{provider_id}", self.get_provider_info)

		web_app.router.add_put("/admin/credentials-ident", self.get_idents_from_ids)

		web_app.router.add_get("/admin/credentials", self.list_credentials)
		web_app.router.add_post("/admin/credentials/{provider}", self.create_credentials)
		web_app.router.add_get("/admin/credentials/{credentials_id}", self.get_credentials)
		web_app.router.add_put("/admin/credentials/{credentials_id}", self.update_credentials)
		web_app.router.add_delete("/admin/credentials/{credentials_id}", self.delete_credentials)

		web_app.router.add_get("/admin/credentials/{credentials_id}/last-login", self.get_last_login_data)
		web_app.router.add_put("/admin/credentials/{credentials_id}/enforce-factors", self.enforce_factors)

		web_app.router.add_get("/account/credentials", self.get_my_credentials)
		web_app.router.add_put("/account/credentials", self.update_my_credentials)
		web_app.router.add_get("/account/credentials/provider", self.get_my_provider_info)
		web_app.router.add_get("/account/credentials/last-login", self.get_my_last_login_data)

		# BACK-COMPAT. Remove after 2025-12-31.
		# >>>
		web_app.router.add_get("/credentials", self.list_credentials)
		web_app.router.add_put("/idents", self.get_idents_from_ids)
		web_app.router.add_put("/usernames", self.get_idents_from_ids)
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
		# <<<


	@asab.web.tenant.allow_no_tenant
	async def list_providers(self, request):
		"""
		Get credential providers and their metadata
		"""
		providers = {}
		for provider_id in self.CredentialsService.CredentialProviders:
			providers[provider_id] = self.CredentialsService.get_provider_info(provider_id)
		return asab.web.rest.json_response(request, providers)


	@asab.web.tenant.allow_no_tenant
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


	@asab.web.tenant.allow_no_tenant
	async def get_my_provider_info(self, request):
		"""
		Get the metadata of the current user's credential provider.
		"""
		authz = asab.contextvars.Authz.get()
		provider = self.CredentialsService.get_provider(authz.CredentialsId)
		data = self.CredentialsService.get_provider_info(provider.ProviderID)
		response = {
			"result": "OK",
			"data": data,
		}
		return asab.web.rest.json_response(request, response)


	@asab.web.tenant.allow_no_tenant
	async def get_last_login_data(self, request):
		"""
		Get the credentials' last successful/failed login data.
		"""
		credentials_id = request.match_info["credentials_id"]
		data = await self.LastActivityService.get_last_logins(credentials_id)
		return asab.web.rest.json_response(request, data)


	@asab.web.tenant.allow_no_tenant
	async def get_my_last_login_data(self, request):
		"""
		Get the current user's last successful/failed login data.
		"""
		authz = asab.contextvars.Authz.get()
		data = await self.LastActivityService.get_last_logins(authz.CredentialsId)
		return asab.web.rest.json_response(request, data)


	@asab.web.tenant.allow_no_tenant
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


	@asab.web.tenant.allow_no_tenant
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
			description: Try to search in all tenants, not only in the currently authorized one
			schema: {"type": "boolean"}
		-	name: astatus
			in: query
			required: false
			description: Filter users by status ("active", "suspended"). If omitted, all statuses are returned ("any").
			schema: {
				"type": "array",
				"items": {"type": "string"},
				"enum": ["active", "suspended", "any"],
				"default": ["any"],
			}
			explode: false
		"""
		authz = asab.contextvars.Authz.get()
		tenant_filter = request.query.get("tenant") or request.query.get("atenant", None)
		role_filter = request.query.get("role") or request.query.get("arole", None)
		simple_filter = request.query.get("f")

		# BACK-COMPAT: Convert the old "mode" search to advanced filters
		mode = request.query.get("m", "default")
		if mode == "tenant":
			tenant_filter = request.query.get("f")
			simple_filter = None

		try_global_search = asab.utils.string_to_boolean(request.query.get("global", "false"))

		authorized_tenants = [t for t in authz.get_claim("resources", {}) if t != "*"]
		if authorized_tenants:
			tenant_ctx = asab.contextvars.Tenant.set(authorized_tenants.pop())
		else:
			tenant_ctx = asab.contextvars.Tenant.set(None)

		status_filter = request.query.get("astatus")
		if status_filter is not None:
			status_filter = status_filter.split(",")
			for status in status_filter:
				if status not in frozenset(["active", "suspended", "any"]):
					raise asab.exceptions.ValidationError(
						"Invalid status filter: {!r}".format(request.query.get("astatus")))
			# If "any" is present, ignore all other status filters
			if "any" in status_filter:
				status_filter = None  # No filtering

		try:
			result = await self.CredentialsService.list(
				page=int(request.query.get("p", 1)) - 1,
				limit=int(request.query.get("i", 10)),
				tenant_filter=tenant_filter,
				role_filter=role_filter,
				simple_filter=simple_filter,
				status_filter=status_filter,
				try_global_search=try_global_search,
			)
		except exceptions.AccessDeniedError as e:
			L.log(asab.LOG_NOTICE, "Cannot list credentials: {}".format(e))
			return asab.web.rest.json_response(request, status=403, data={
				"result": "ACCESS-DENIED",
			})
		finally:
			asab.contextvars.Tenant.reset(tenant_ctx)

		return asab.web.rest.json_response(request, {
			"result": "OK",
			**result
		})


	@asab.web.rest.json_schema_handler(schema.GET_IDENTS_FROM_IDS)
	@asab.web.tenant.allow_no_tenant
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
			ident = cred_obj.get("label") \
				or cred_obj.get("username") \
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


	@asab.web.tenant.allow_no_tenant
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
		authz = asab.contextvars.Authz.get()
		credentials_id = request.match_info["credentials_id"]

		# Check authorization:
		#   the requester must be authorized in at least one of the tenants that the requested is a member of
		if not authz.has_superuser_access():
			authorized_tenants = [t for t in authz.get_claim("resources", {}) if t != "*"]
			for tenant in authorized_tenants:
				if tenant == "*":
					continue
				if await self.TenantService.has_tenant_assigned(credentials_id, tenant):
					# Found a common tenant
					break
				else:
					continue
			else:
				# No tenant in common
				return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)

		provider = self.CredentialsService.get_provider(credentials_id)

		try:
			credentials = await provider.get(request.match_info["credentials_id"])
		except KeyError:
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)

		if asab.config.utils.string_to_boolean(request.query.get("last_login", "no")):
			credentials["_ll"] = await self.LastActivityService.get_last_logins(credentials_id)

		credentials["actions"] = await self.CredentialsService.get_allowed_actions(credentials)

		return asab.web.rest.json_response(request, credentials)


	@asab.web.rest.json_schema_handler(schema.CREATE_CREDENTIALS)
	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.CREDENTIALS_EDIT)
	async def create_credentials(self, request, *, json_data):
		"""
		Create new credentials
		"""
		reset_password = json_data.pop("passwordlink", False)
		provider_id = request.match_info["provider"]
		provider = self.CredentialsService.CredentialProviders[provider_id]

		# Create credentials
		result = await self.CredentialsService.create_credentials(provider_id, json_data)

		if result["status"] != "OK":
			result["result"] = result["status"]
			return asab.web.rest.json_response(request, result, status=400)

		credentials_id = result["credentials_id"]

		response_data = {
			"result": "OK",
			"status": "OK",  # Backward compatibility
			"_id": credentials_id,
			"_type": provider.Type,
			"_provider_id": provider.ProviderID,
		}

		if reset_password:
			change_pwd_svc = self.App.get_service("seacatauth.ChangePasswordService")
			comm_svc = self.App.get_service("seacatauth.CommunicationService")
			credentials = await self.CredentialsService.get(credentials_id)

			# Check if password reset link can be sent (in email or at least in the response)
			authz = asab.contextvars.Authz.get()
			if not (
				authz.has_superuser_access()
				or await comm_svc.can_send_to_target(credentials, "email")
			):
				L.error("Password reset denied: No way to communicate password reset link.", struct_data={
					"cid": credentials_id})
				password_reset_response = {
					"result": "ERROR",
					"tech_err": "Password reset link cannot be sent.",
				}
				response_data["password_reset"] = password_reset_response
				return asab.web.rest.json_response(request, response_data)

			password_reset_response = {}

			# Create the password reset link
			password_reset_url = await change_pwd_svc.init_password_reset(
				credentials,
				expiration=json_data.get("expiration"),
			)

			# Superusers receive the password reset link in response
			if authz.has_superuser_access():
				password_reset_response["password_reset_url"] = password_reset_url

			# Email the link to the user
			try:
				await comm_svc.password_reset(
					credentials=credentials,
					reset_url=password_reset_url,
					new_user=True
				)
			except exceptions.ServerCommunicationError:
				password_reset_response["result"] = "ERROR"
				password_reset_response["tech_err"] = "Cannot connect to email service"
				response_data["password_reset"] = password_reset_response
				return asab.web.rest.json_response(request, response_data)
			except exceptions.MessageDeliveryError:
				password_reset_response["result"] = "ERROR"
				password_reset_response["tech_err"] = "Failed to send password reset link."
				response_data["password_reset"] = password_reset_response
				return asab.web.rest.json_response(request, response_data)

			password_reset_response["result"] = "OK"
			response_data["password_reset"] = password_reset_response

		return asab.web.rest.json_response(request, response_data)


	@asab.web.rest.json_schema_handler(schema.UPDATE_CREDENTIALS)
	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.CREDENTIALS_EDIT)
	async def update_credentials(self, request, *, json_data):
		"""
		Update credentials
		"""
		credentials_id = request.match_info["credentials_id"]

		# Update credentials
		result = await self.CredentialsService.update_credentials(credentials_id, json_data)

		result["result"] = result["status"]  # TODO: Unify response format

		if result["result"] != "OK":
			return asab.web.rest.json_response(request, result, status=400)

		return asab.web.rest.json_response(request, result)


	@asab.web.rest.json_schema_handler(schema.UPDATE_MY_CREDENTIALS)
	@asab.web.tenant.allow_no_tenant
	async def update_my_credentials(self, request, *, json_data):
		"""
		Update the current user's own credentials
		"""
		authz = asab.contextvars.Authz.get()
		result = await self.CredentialsService.update_credentials(
			authz.CredentialsId,
			json_data,
		)

		result["result"] = result["status"]  # TODO: Unify response format

		if result["status"] != "OK":
			return asab.web.rest.json_response(request, result, status=400)

		return asab.web.rest.json_response(request, result)


	@asab.web.tenant.allow_no_tenant
	async def get_my_credentials(self, request):
		"""
		Get the current user's own credentials

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
		authz = asab.contextvars.Authz.get()
		result = await self.CredentialsService.get(authz.CredentialsId)

		if asab.config.utils.string_to_boolean(request.query.get("last_login", "no")):
			result["_ll"] = await self.LastActivityService.get_last_logins(authz.CredentialsId)

		return asab.web.rest.json_response(request, result)


	@asab.web.rest.json_schema_handler(schema.ENFORCE_FACTORS)
	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.CREDENTIALS_EDIT)
	async def enforce_factors(self, request, *, json_data):
		"""
		Specify authentication factors to be enforced from the user
		"""
		credentials_id = request.match_info["credentials_id"]
		provider = self.CredentialsService.get_provider(credentials_id)

		enforce_factors = json_data.get("factors")

		for factor in enforce_factors:
			if factor not in frozenset(["totp", "smscode", "password"]):
				raise ValueError("Login factor cannot be enforced", {"factor": factor})

		result = await provider.update(credentials_id, {
			"enforce_factors": enforce_factors
		})

		return asab.web.rest.json_response(request, {"result": result})


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require_superuser
	async def delete_credentials(self, request):
		"""
		Delete credentials
		"""
		authz = asab.contextvars.Authz.get()
		credentials_id = request.match_info["credentials_id"]  # Who will be deleted
		result = await self.CredentialsService.delete_credentials(credentials_id, authz.CredentialsId)
		return asab.web.rest.json_response(request, {"result": result})
