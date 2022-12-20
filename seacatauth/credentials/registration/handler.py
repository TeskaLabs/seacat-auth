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
		web_app.router.add_put("/public/register/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.update_registration)
		web_app.router.add_post(
			"/public/register/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.complete_registration)

		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_post("/public/register", self.request_self_invitation)
		web_app_public.router.add_get("/public/register/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.get_registration)
		web_app_public.router.add_put("/public/register/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.update_registration)
		web_app_public.router.add_post(
			"/public/register/{registration_code:[-_=a-zA-Z0-9]{16,}}", self.complete_registration)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["credentials"],
		"additionalProperties": False,
		"properties": {
			"credentials": {
				"required": ["email"],  # TODO: Enable more communication options
				"properties": {
					"email": {"type": "string"},
					"username": {"type": "string"},
					"phone": {"type": "string"},
				}
			},
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
		if isinstance(expiration, str):
			expiration = asab.utils.convert_to_seconds(expiration)

		credential_data = json_data["credentials"]

		# Create invitation
		invited_credentials_id, registration_code = await self.RegistrationService.draft_credentials(
			credential_data=credential_data,
			expiration=expiration,
			invited_by_cid=credentials_id,
			invited_from_ips=access_ips,
		)

		# Assign tenant
		await self.RegistrationService.TenantService.assign_tenant(invited_credentials_id, tenant)

		# Send invitation
		await self.RegistrationService.CommunicationService.registration_link(
			email=credential_data.get("email"),
			registration_uri=self.RegistrationService.format_registration_uri(registration_code),
			username=credential_data.get("username"),
			tenant=tenant
		)

		payload = {
			"credentials_id": invited_credentials_id,
		}

		return asab.web.rest.json_response(request, payload)


	@access_control("authz:tenant:admin")
	async def resend_invitation(self, request):
		credentials_id = request.match_info["credentials_id"]
		credentials = await self.CredentialsService.get(credentials_id, include=["__registration"])

		if "__registration" not in credentials:
			raise asab.exceptions.ValidationError("Credentials already registered.")
		assert "email" in credentials

		tenants = await self.RegistrationService.TenantService.get_tenants(credentials_id)
		try:
			tenant = tenants[0]
		except IndexError:
			tenant = None

		await self.RegistrationService.CommunicationService.registration_link(
			email=credentials["email"],
			registration_uri=self.RegistrationService.format_registration_uri(credentials["__registration"]["code"]),
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

		# TODO: Get "required" and "editable" values from credential policy
		email_data = {
			"required": True,
			"editable": False,
		}
		if "email" in credentials:
			email_data["value"] = credentials["email"]

		phone_data = {
			"required": False,
			"editable": True,
		}
		if "phone" in credentials:
			phone_data["value"] = credentials["phone"]

		username_data = {
			"required": True,
			"editable": True,
		}
		if "username" in credentials:
			username_data["value"] = credentials["username"]

		password_hash = credentials.pop("__password", None)
		password_data = {
			"set": password_hash is not None and len(password_hash) > 0,
			"required": True,
			"editable": True,
		}
		# TODO: Add info about configured login factors
		# credentials_public["totp"] = False
		# credentials_public["webauthn"] = False
		# credentials_public["external_login"] = False

		response_data = {
			"credentials": {
				"email": email_data,
				"username": username_data,
				"phone": phone_data,
				"password": password_data,
			}
		}
		tenants = await self.TenantService.get_tenants(credentials["_id"])
		if tenants is not None:
			response_data["tenants"] = tenants

		return asab.web.rest.json_response(request, response_data)


	async def update_registration(self, request):
		"""
		Update drafted credentials
		"""
		registration_code = request.match_info["registration_code"]

		request_data = await request.read()
		if self.RegistrationService.EncryptionEnabled:
			raise NotImplementedError("Registration encryption not implemented.")
		else:
			try:
				credential_data = json.loads(request_data)
			except json.decoder.JSONDecodeError:
				raise asab.exceptions.ValidationError("Invalid JSON.")

		await self.RegistrationService.update_credential_by_registration_code(
			registration_code, credential_data)

		return asab.web.rest.json_response(request, {"result": "OK"})



	async def complete_registration(self, request):
		"""
		Complete the registration either by activating the draft credentials
		or by transferring their tenants and roles to the currently authenticated user.
		"""
		registration_code = request.match_info["registration_code"]

		# TODO: Make sure that self-registered users create their new tenant

		if request.Session is not None:
			# Use the registration data to update the currently authenticated user
			# Make sure this is explicit
			if request.query.get("update_current") != "true":
				raise asab.exceptions.ValidationError(
					"To complete the registration with your current credentials, "
					"include 'update_current=true' in the query.")
			credentials_id = request.Session.Credentials.Id
			await self.RegistrationService.complete_registration_with_existing_credentials(
				registration_code, credentials_id)

		else:
			# Complete the registration with the new credentials
			await self.RegistrationService.complete_registration(registration_code)

		return asab.web.rest.json_response(request, {"result": "OK"})
