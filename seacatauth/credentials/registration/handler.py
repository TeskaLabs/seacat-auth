import json
import secrets
import logging

import aiohttp
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
		web_app.router.add_get("/{tenant}/invite", self.get_invitation_features)
		web_app.router.add_post("/{tenant}/invite", self.create_invitation)
		web_app.router.add_post("/public/register", self.request_self_invitation)
		web_app.router.add_get("/public/register/{invitation_code:[-_=a-zA-Z0-9]{16,}}", self.get_invitation_details)
		web_app.router.add_put("/public/register/prologue", self.registration_prologue)
		web_app.router.add_put("/public/register/{registration_session_id:[-_=a-zA-Z0-9]{16,}}", self.register)

		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_post("/public/register", self.request_self_invitation)
		web_app_public.router.add_get("/public/register/{invitation_code:[-_=a-zA-Z0-9]{16,}}", self.get_invitation_details)
		web_app_public.router.add_put("/public/register/prologue", self.registration_prologue)
		web_app_public.router.add_put("/public/register/{registration_session_id:[-_=a-zA-Z0-9]{16,}}", self.register)


	@access_control("authz:tenant:admin")
	async def get_invitation_features(self, request, *, tenant):
		"""
		Returns a JSON response with the features of the invitation

		:param request: The request object
		:param tenant: The tenant to register the new user into
		:return: Invitation features
		"""
		# TODO: Get invitation features from provider + config
		# features = self.RegistrationService.get_invitation_features(tenant)
		features = {
			"type": "object",
			"required": ["email"],
			"additionalProperties": False,
			"properties": {
				"roles": {
					"type": "array", "description": "Roles to be assigned to the new user."},
				"email": {
					"type": "string", "description": "User email to send the invitation to."},
				"provider_id": {
					"type": "string", "description": "Credentials provider used for the registration."},
				"expiration": {
					"oneOf": [{"type": "string"}, {"type": "number"}],
					"description": "How long until the invitation expires.",
					"examples": ["6 h", "3d", "1w", 7200]},
			},
		}

		return asab.web.rest.json_response(request, {"features": features})


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["email"],
		"additionalProperties": False,
		"properties": {
			"roles": {
				"type": "array", "description": "Roles to assign to the new user."},
			"email": {
				"type": "string", "description": "User email to send the invitation to."},
			"provider_id": {
				"type": "string", "description": "Credentials provider used for the registration."},
			"expiration": {
				"oneOf": [{"type": "string"}, {"type": "number"}],
				"description": "How long until the invitation expires.",
				"examples": ["6 h", "3d", "1w", 7200]},
		},
	})
	@access_control("authz:tenant:admin")  # TODO: Maybe create a dedicated resource for invitation
	async def create_invitation(self, request, *, tenant, credentials_id, json_data):
		"""
		Admin request to register a new user and invite them to specified tenant.
		Generate a registration token and send a registration link to the user's email.
		"""
		# Get IPs of the invitation issuer
		access_ips = [request.remote]
		forwarded_for = request.headers.get("X-Forwarded-For")
		if forwarded_for is not None:
			access_ips.extend(forwarded_for.split(", "))

		expiration = json_data.get("expiration")
		if expiration is not None:
			expiration = asab.utils.convert_to_seconds(expiration)
		else:
			expiration = self.RegistrationService.InviteExpiration

		# Create invitation
		invitation_id = await self.RegistrationService.invite(
			tenant=tenant,
			roles=json_data.get("roles"),
			email=json_data.get("email"),
			provider_id=json_data.get("provider_id"),
			expiration=expiration,
			invited_by_cid=credentials_id,
			invited_by_ips=access_ips,
		)

		payload = {
			"invitation_code": invitation_id,
			"registration_uri": self.RegistrationService.format_registration_uri(invitation_id),
		}

		return asab.web.rest.json_response(request, payload)


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

		# Create invitation
		await self.RegistrationService.invite(
			tenant=None,
			email=json_data.get("email"),
			invited_by_ips=access_ips,
		)

		payload = {
			"result": "OK",
			"email": json_data.get("email"),
		}

		return asab.web.rest.json_response(request, payload)


	async def get_invitation_details(self, request):
		"""
		Get information about the specified registration token
		"""
		# TODO: Limit the total number of active registrations
		# TODO: Limit the number of active registrations from a single IP
		invitation_id = request.match_info["invitation_code"]
		invitation = await self.RegistrationService.get_invitation_detail(invitation_id)
		credentials = invitation.get("c")
		response = {
			"id": invitation_id,
			"email": credentials["email"],
		}

		if credentials.get("tenant") is not None:
			# Invited by tenant admin
			response["tenant"] = credentials["tenant"]
		else:
			# Request for self-registration
			if not self.RegistrationService.SelfRegistrationAllowed:
				# Self-registration is not allowed
				raise aiohttp.web.HTTPForbidden()

		return asab.web.rest.json_response(request, response)


	async def registration_prologue(self, request):
		invitation_id = request.query.get("invitation_code")
		registration_session = await self.RegistrationService.create_registration_session(invitation_id)
		response = {
			"rsid": registration_session.Id,
		}

		if self.RegistrationService.RegistrationEncrypted:
			# TODO: Initiate E2E-encrypted session
			# key = jwcrypto.jwk.JWK.from_pyca(registration_session.PublicKey)
			# response["key"] = key.export_public(as_dict=True)
			raise NotImplementedError()

		return asab.web.rest.json_response(request, response)


	async def register(self, request):
		"""
		Validate registration data and create credentials (and tenant, if needed)
		"""
		rsid = request.match_info["registration_session_id"]

		registration_session = await self.RegistrationService.get_login_session(rsid)

		req_data = await request.read()

		if self.RegistrationService.RegistrationEncrypted:
			# TODO: Decrypt the payload
			# request_data = registration_session.decrypt(await request.read())
			raise NotImplementedError()

		try:
			registration_data = json.loads(req_data)
		except json.decoder.JSONDecodeError:
			return asab.exceptions.ValidationError("Invalid JSON.")

		result = await self.CredentialsService.register_credentials(registration_session, **registration_data)

		return asab.web.rest.json_response(request, result)
