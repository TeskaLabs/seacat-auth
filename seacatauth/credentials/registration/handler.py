import datetime
import json
import logging
import typing
import aiohttp.web

import asab
import asab.web.rest
import asab.utils
import asab.exceptions

from ... import generic, exceptions
from ...models.const import ResourceId
from ...decorators import access_control
from .. import schema


L = logging.getLogger(__name__)


class RegistrationHandler(object):
	"""
	Credential registration

	---
	tags: ["User registration"]
	"""

	def __init__(self, app, registration_svc, credentials_svc):
		self.RegistrationService = registration_svc
		self.CredentialsService = credentials_svc

		self.SessionService = app.get_service("seacatauth.SessionService")
		self.TenantService = app.get_service("seacatauth.TenantService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_post("/{tenant}/invite", self.admin_create_invitation)
		web_app.router.add_post("/invite/{credentials_id}", self.resend_invitation)
		web_app.router.add_post("/account/{tenant}/invite", self.public_create_invitation)
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


	@asab.web.rest.json_schema_handler(schema.CREATE_INVITATION_PUBLIC)
	@access_control(ResourceId.TENANT_ASSIGN)
	async def public_create_invitation(self, request, *, tenant, credentials_id, json_data):
		"""
		Common user request to invite a new user to join specified tenant and create an account
		if they don't have one yet. The invited user gets a registration link in their email.
		"""
		# TODO: Limit the number of requests
		# Get IPs of the invitation issuer
		access_ips = [request.remote]
		forwarded_for = request.headers.get("X-Forwarded-For")
		if forwarded_for is not None:
			access_ips.extend(forwarded_for.split(", "))

		expiration = json_data.get("expiration")
		if isinstance(expiration, str):
			expiration = asab.utils.convert_to_seconds(expiration)
		else:
			expiration = self.RegistrationService.RegistrationExpiration

		credential_data = {"email": json_data.get("email")}

		# Prepare credentials, assign tenant and send invitation email
		return await self._prepare_invitation(
			request, tenant, credential_data, expiration, access_ips,
			invited_by_cid=credentials_id
		)


	@asab.web.rest.json_schema_handler(schema.CREATE_INVITATION_ADMIN)
	@access_control(ResourceId.TENANT_ASSIGN)
	async def admin_create_invitation(self, request, *, tenant, credentials_id, json_data):
		"""
		Admin request to register a new user and invite them to the specified tenant.
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
		else:
			expiration = self.RegistrationService.RegistrationExpiration

		credential_data = json_data["credentials"]

		# Prepare credentials and assign tenant
		return await self._prepare_invitation(
			request, tenant, credential_data, expiration, access_ips,
			invited_by_cid=credentials_id
		)


	async def _prepare_invitation(
		self,
		request: aiohttp.web.Request,
		tenant: str,
		credential_data: dict,
		expiration: float,
		access_ips: list,
		invited_by_cid: typing.Optional[str] = None,
	) -> aiohttp.web.Response:
		"""
		Prepare credentials for registration. Either create a new set of credentials, or locate the existing one.

		Args:
			tenant: Tenant to invite into
			credential_data: Username, email address and/or phone number
			expiration: Invitation expiration in seconds
			access_ips: Source IPs of the invitation request
			invited_by_cid: Credentials ID of the invitation request
		"""
		session_ctx = generic.SessionContext.get()
		can_send_email = (
			"email" in credential_data
			and await self.RegistrationService.CommunicationService.is_channel_enabled("email")
		)
		if not (can_send_email or session_ctx.is_superuser()):
			# Cannot send email, cannot return link in response
			return asab.web.rest.json_response(request, status=400, data={
				"result": "ERROR",
				"tech_err": "Sending emails is not supported."
			})

		# Prepare credentials and registration code
		already_registered = False
		try:
			credentials_id = await self.RegistrationService.draft_credentials(
				credential_data=credential_data,
				expiration=expiration,
				invited_by_cid=invited_by_cid,
				invited_from_ips=access_ips,
			)

		except asab.exceptions.Conflict:
			# Credentials already exist
			# Locate the credentials by the conflicting value and use them
			credentials_id = await self.CredentialsService.locate(credential_data["email"], stop_at_first=True)
			credentials = await self.CredentialsService.get(credentials_id, include=["__registration"])

			if "__registration" not in credentials:
				already_registered = True
				L.log(
					asab.LOG_NOTICE,
					"Invitation matches credentials that are already registered.",
					struct_data={"cid": credentials_id, **credential_data}
				)


		# Assign tenant
		try:
			await self.RegistrationService.TenantService.assign_tenant(credentials_id, tenant)
		except asab.exceptions.Conflict:
			L.log(asab.LOG_NOTICE, "Tenant already assigned.", struct_data={"cid": credentials_id, "t": tenant})

		response_data = {
			"result": "OK",
			"credentials_id": credentials_id,
		}

		if not already_registered:
			registration_code = await self.RegistrationService.refresh_registration_code(credentials_id)
			registration_url = self.RegistrationService.format_registration_url(registration_code)
			if session_ctx.is_superuser():
				response_data["registration_url"] = registration_url

			if not can_send_email:
				response_data["result"] = "ERROR"
				response_data["tech_err"] = "Failed to send invitation link."
				return asab.web.rest.json_response(request, response_data, status=400)

			try:
				await self.RegistrationService.CommunicationService.invitation(
					credentials=credential_data,
					registration_uri=registration_url,
					tenants=[tenant],
					expires_at=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=expiration)
				)
			except exceptions.MessageDeliveryError:
				response_data["result"] = "ERROR"
				response_data["tech_err"] = "Failed to send invitation link."
				return asab.web.rest.json_response(request, response_data, status=400)

		return asab.web.rest.json_response(request, response_data)


	@access_control(ResourceId.TENANT_ASSIGN)
	async def resend_invitation(self, request):
		"""
		Resend invitation to an already invited user and extend the expiration of the invitation.
		"""
		session_ctx = generic.SessionContext.get()
		credentials_id = request.match_info["credentials_id"]
		credentials = await self.CredentialsService.get(credentials_id, include=["__registration"])
		can_send_email = await self.RegistrationService.CommunicationService.can_send_to_target(credentials, "email")
		if not (can_send_email or session_ctx.is_superuser()):
			# Cannot send email, cannot return link in response
			return asab.web.rest.json_response(request, status=400, data={
				"result": "ERROR",
				"tech_err": "Sending emails is not supported."
			})

		if "__registration" not in credentials:
			raise asab.exceptions.ValidationError("Credentials already registered.")
		assert "email" in credentials

		# Extend the expiration
		expiration = (
			datetime.datetime.now(datetime.timezone.utc)
			+ datetime.timedelta(seconds=self.RegistrationService.RegistrationExpiration))
		if credentials["__registration"]["exp"] < expiration:
			await self.RegistrationService.CredentialProvider.update(
				credentials["_id"], {"__registration.exp": expiration})
		else:
			expiration = credentials["__registration"]["exp"]

		registration_code = await self.RegistrationService.refresh_registration_code(credentials_id)
		registration_url = self.RegistrationService.format_registration_url(registration_code)

		response_data = {"result": "OK"}
		if session_ctx.is_superuser():
			response_data["registration_url"] = registration_url

		if not can_send_email:
			response_data["result"] = "ERROR"
			response_data["tech_err"] = "Failed to send invitation link."
			return asab.web.rest.json_response(request, response_data, status=400)

		tenants = await self.RegistrationService.TenantService.get_tenants(credentials_id)
		try:
			await self.RegistrationService.CommunicationService.invitation(
				credentials=credentials,
				registration_uri=registration_url,
				tenants=tenants,
				expires_at=expiration,
			)
		except exceptions.MessageDeliveryError:
			response_data["result"] = "ERROR"
			response_data["tech_err"] = "Failed to send invitation link."
			return asab.web.rest.json_response(request, response_data, status=400)

		return asab.web.rest.json_response(request, response_data)


	@asab.web.rest.json_schema_handler(schema.REQUEST_SELF_INVITATION)
	async def request_self_invitation(self, request, *, json_data):
		"""
		Anonymous user request to register themself.
		Generate a registration token and send a registration link to the user's email.
		"""
		# Disable this endpoint if self-registration is not enabled
		if not self.RegistrationService.SelfRegistrationEnabled:
			L.log(asab.LOG_NOTICE, "Self-registration is not enabled")
			return aiohttp.web.HTTPNotFound()

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
		try:
			credentials = await self.RegistrationService.get_credential_by_registration_code(registration_code)
		except KeyError:
			return asab.web.rest.json_response(request, status=404, data={
				"result": "ERROR",
				"tech_err": "Registration code not found."
			})

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
