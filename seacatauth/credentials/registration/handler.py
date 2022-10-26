import json
import logging
import aiohttp.web

import asab
import asab.web.rest
import asab.utils
import asab.exceptions

from ...decorators import access_control

#

L = logging.getLogger(__name__)

#


class RegistrationHandler(object):

	def __init__(self, app, registration_svc, credentials_svc):
		self.RegistrationService = registration_svc
		self.CredentialsService = credentials_svc

		self.SessionService = app.get_service("seacatauth.SessionService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.AuditService = app.get_service("seacatauth.AuditService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_post("/{tenant}/invite", self.create_invitation)
		web_app.router.add_post("/invite/{credentials_id}", self.resend_invitation)
		web_app.router.add_post("/public/register", self.request_self_invitation)
		web_app.router.add_get("/public/register/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.get_registration)
		web_app.router.add_put("/public/register/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.register)
		web_app.router.add_post(
			"/public/register/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.register_with_current_credentials)

		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_post("/public/register", self.request_self_invitation)
		web_app_public.router.add_get("/public/register/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.get_registration)
		web_app_public.router.add_put("/public/register/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.register)
		web_app_public.router.add_post(
			"/public/register/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.register_with_current_credentials)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["email"],  # TODO: Enable more communication options
		"additionalProperties": False,
		"properties": {
			"email": {
				"type": "string"},
			"expiration": {
				"oneOf": [{"type": "string"}, {"type": "number"}],
				"description": "How long until the invitation expires.",
				"examples": ["6 h", "3d", "1w", 7200]},
		},
	})
	@access_control("authz:tenant:admin")  # TODO: Maybe create a dedicated resource for invitations
	async def create_invitation(self, request, *, tenant, credentials_id, json_data):
		"""
		Admin request to register a new user and invite them to specified tenant.
		Generate a registration code and send a registration link to the user's email.
		"""
		# Get IPs of the invitation issuer
		access_ips = [request.remote]
		forwarded_for = request.headers.get("X-Forwarded-For")
		if forwarded_for is not None:
			access_ips.extend(forwarded_for.split(", "))

		expiration = json_data.get("expiration")
		if expiration is not None:
			expiration = asab.utils.convert_to_seconds(expiration)

		# Create invitation
		invited_credentials_id, registration_code = await self.RegistrationService.draft_credentials(
			credential_data={"email": json_data["email"]},
			expiration=expiration,
			invited_by_cid=credentials_id,
			invited_from_ips=access_ips,
		)

		# Assign tenant
		await self.RegistrationService.TenantService.assign_tenant(invited_credentials_id, tenant)

		# Send invitation
		await self.RegistrationService.CommunicationService.registration_link(
			email=json_data.get("email"),
			registration_uri=self.RegistrationService.format_registration_uri(registration_code),
			username=json_data.get("username"),
			tenant=tenant
		)

		payload = {
			"credentials_id": invited_credentials_id,
		}

		return asab.web.rest.json_response(request, payload)


	@access_control("authz:tenant:admin")
	async def resend_invitation(self, request):
		credentials_id = request.match_info["credentials_id"]
		credentials = await self.CredentialsService.get(credentials_id)

		if credentials.get("reg", {}).get("code") is None:
			raise KeyError("Credentials not found")
		assert "email" in credentials

		tenants = await self.RegistrationService.TenantService.get_tenants(credentials_id)
		try:
			tenant = tenants[0]
		except IndexError:
			tenant = None

		await self.RegistrationService.CommunicationService.registration_link(
			email=credentials["email"],
			registration_uri=self.RegistrationService.format_registration_uri(credentials["reg"]["code"]),
			username=credentials.get("username"),
			tenant=tenant
		)

		return asab.web.rest.json_response(request, {"result": "OK"})


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["email"],
		"additionalProperties": False,
		"properties": {
			"email": {
				"type": "string",
				"description": "User email to send the invitation to."},
		},
	})
	async def request_self_invitation(self, request, *, json_data):
		"""
		Anonymous user request to register themself.
		Generate a registration token and send a registration link to the user's email.
		"""
		# Disable this endpoint if self-registration is not enabled
		if not self.RegistrationService.SelfRegistrationEnabled:
			raise aiohttp.web.HTTPNotFound()

		# Log IPs from which the request was made
		access_ips = [request.remote]
		forwarded_for = request.headers.get("X-Forwarded-For")
		if forwarded_for is not None:
			access_ips.extend(forwarded_for.split(", "))

		# TODO: Limit the number of self-registrations with the same IP / same email address
		# TODO: Limit the total number of active registrations

		# Create invitation
		await self.RegistrationService.draft_credentials(
			credential_data={"email": json_data["email"]},
			invited_from_ips=access_ips,
		)

		payload = {
			"result": "OK",
			"email": json_data.get("email"),
		}

		return asab.web.rest.json_response(request, payload)


	async def get_registration(self, request):
		"""
		Get credentials by registration handle
		"""
		registration_code = request.match_info["registration_code"]
		credentials = await self.RegistrationService.get_credential_by_registration_code(registration_code)

		return asab.web.rest.json_response(request, credentials)


	async def register(self, request):
		"""
		Validate registration data and create credentials (and tenant, if needed)
		"""
		registration_code = request.match_info["registration_code"]

		request_data = await request.read()
		if self.RegistrationService.EncryptionEnabled:
			raise NotImplementedError("Registration encryption not implemented.")
		else:
			try:
				credential_data = json.loads(request_data)
			except json.decoder.JSONDecodeError:
				return asab.exceptions.ValidationError("Invalid JSON.")

		await self.RegistrationService.update_credential_by_registration_code(
			registration_code, credential_data)

		result = "CREDENTIALS-UPDATED"
		try:
			await self.RegistrationService.complete_registration(registration_code)
			result = "REGISTRATION-COMPLETE"
		except asab.exceptions.ValidationError as e:
			L.info("Registration not completed: {}".format(e))

		return asab.web.rest.json_response(request, {"result": result})


	@access_control()
	async def register_with_current_credentials(self, request, *, credentials_id):
		"""
		Use the registration object to register current user to the tenant
		"""
		registration_code = request.match_info["registration_code"]

		reg_credentials = await self.RegistrationService.get_credential_by_registration_code(registration_code)
		reg_credential_id = reg_credentials["_id"]
		reg_tenants = await self.RegistrationService.TenantService.get_tenants(reg_credential_id)
		reg_roles = await self.RegistrationService.RoleService.get_roles_by_credentials(
			reg_credential_id, reg_tenants)
		for tenant in reg_tenants:
			await self.RegistrationService.TenantService.assign_tenant(credentials_id, tenant)
		for role in reg_roles:
			await self.RegistrationService.RoleService.assign_role(credentials_id, role)
		await self.CredentialsService.delete_credentials(reg_credential_id)
		L.log(asab.LOG_NOTICE, "Credentials registered to a new tenant", struct_data={
			"cid": credentials_id,
			"reg_cid": reg_credential_id,
			"tenants": ", ".join(reg_tenants),
			"roles": ", ".join(reg_roles),
		})
		return asab.web.rest.json_response(request, {"result": "OK"})
