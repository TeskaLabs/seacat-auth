import json
import logging

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
		web_app.router.add_post("/invite/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.resend_invitation)
		web_app.router.add_post("/public/register", self.request_self_invitation)
		web_app.router.add_get("/public/register/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.get_registration)
		web_app.router.add_put("/public/register/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.register)

		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_post("/public/register", self.request_self_invitation)
		web_app_public.router.add_get("/public/register/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.get_registration)
		web_app_public.router.add_put("/public/register/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.register)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["email"],
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
		credentials_id = await self.RegistrationService.draft_credentials(
			credential_data={"email": json_data["email"]},
			expiration=expiration,
			invited_by_cid=credentials_id,
			invited_from_ips=access_ips,
		)

		await self.RegistrationService.TenantService.assign_tenant(credentials_id, tenant)

		payload = {
			"credentials_id": credentials_id,
		}

		return asab.web.rest.json_response(request, payload)


	@access_control("authz:tenant:admin")
	async def resend_invitation(self, request):
		registration_code = request.match_info["registration_code"]
		credentials = await self.RegistrationService.get_credential_by_registration_code(registration_code)

		# TODO: Send invitation via mail
		# await self.CommunicationService.registration_link(email=email, registration_uri=registration_uri)
		L.log(asab.LOG_NOTICE, "Sending invitation", struct_data={
			"email": credentials["email"],
			"credential_id": credentials["_id"],
			"registration_uri": self.RegistrationService.format_registration_uri(registration_code),
		})

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
		request_data = await request.read()
		if self.RegistrationService.RegistrationEncrypted:
			raise NotImplementedError("Registration encryption not implemented.")
		else:
			try:
				credential_data = json.loads(request_data)
			except json.decoder.JSONDecodeError:
				return asab.exceptions.ValidationError("Invalid JSON.")

		registration_code = request.match_info["registration_code"]
		await self.RegistrationService.update_credential_by_registration_code(
			registration_code, credential_data)

		result = {"credentials_updated": True}
		try:
			await self.RegistrationService.complete_registration(registration_code)
			result["registration_complete"] = True
		except asab.exceptions.ValidationError as e:
			L.warning(str(e))
			result["registration_complete"] = False

		return asab.web.rest.json_response(request, result)
