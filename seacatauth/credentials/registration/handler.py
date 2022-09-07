import json
import secrets
import logging

import aiohttp
import aiohttp.web

import asab
import asab.web.rest
import asab.utils

import jwcrypto

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
		web_app.router.add_post("/public/register", self.request_self_registration)
		web_app.router.add_get("/public/register/{registration_token:[-_=a-zA-Z0-9]{16,}}", self.get_registration_token)
		web_app.router.add_put("/public/register/prologue", self.registration_prologue)
		web_app.router.add_put("/public/register/{registration_token:[-_=a-zA-Z0-9]{16,}}", self.register)

		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_post("/public/register", self.request_self_registration)
		web_app_public.router.add_get("/public/register/{registration_token:[-_=a-zA-Z0-9]{16,}}", self.get_registration_token)
		web_app_public.router.add_put("/public/register/prologue", self.registration_prologue)
		web_app_public.router.add_put("/public/register/{registration_token:[-_=a-zA-Z0-9]{16,}}", self.register)

		self.RegistrationEncrypted = asab.Config.getboolean("general", "registration_encrypted")


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

		# Create invitation
		token_id = await self.RegistrationService.create_invitation(
			tenant=tenant,
			roles=json_data.get("roles"),
			email=json_data.get("email"),
			provider_id=json_data.get("provider_id"),
			expiration=asab.utils.convert_to_seconds(json_data.get("expiration")),
			invited_by_cid=credentials_id,
			invited_by_ips=access_ips,
		)

		payload = {
			"registration_token": token_id,
			"registration_uri": self.RegistrationService.format_registration_uri(token_id),
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
	async def request_self_registration(self, request, *, json_data):
		"""
		Anonymous user request to register themself.
		Generate a registration token and send a registration link to the user's email.
		"""
		# Get IPs of the user who requested the registration
		access_ips = [request.remote]
		forwarded_for = request.headers.get("X-Forwarded-For")
		if forwarded_for is not None:
			access_ips.extend(forwarded_for.split(", "))

		# Create invitation
		token_id = await self.RegistrationService.create_invitation(
			tenant=None,
			email=json_data.get("email"),
			invited_by_ips=access_ips,
		)

		payload = {
			"registration_token": token_id,
			"registration_uri": self.RegistrationService.format_registration_uri(token_id),
		}

		return asab.web.rest.json_response(request, payload)


	async def get_registration_token(self, request):
		"""
		Get information about the specified registration token
		"""
		# TODO: Initiate E2E-encrypted session
		# TODO: Limit the total number of active registrations
		# TODO: Limit the number of active registrations from a single IP
		token_id = request.match_info["registration_token"]
		token = await self.RegistrationService.get_registration_token(token_id)

		assert token.get("t") is not None

		if request.Session is not None:
			# A user is logged in
			# Update the token with the user's credentials ID
			# Return token data
			...
		else:
			# User is not logged in
			...

		if token_id is None:
			# User-initiated public registration
			# TODO: Check if open registration is enabled

			# Get IPs of the requester
			access_ips = [request.remote]
			forwarded_for = request.headers.get("X-Forwarded-For")
			if forwarded_for is not None:
				access_ips.extend(forwarded_for.split(", "))
			token_id = await self.RegistrationService.create_registration_token(
				expiration=self.RegistrationService.OpenRegistrationExpiration,
				invited_by_ips=access_ips,
			)

		token_data = await self.RegistrationService.get_registration_token(token_id)

		return asab.web.rest.json_response(request, token_data)


	async def registration_prologue(self, request):
		pass


	async def register(self, request):
		"""
		Validate registration data and create credentials (and tenant, if needed)

		Scenarios:
		1) User is logged in
			a) Registration request has a tenant
				-> Add the user to the tenant
			b) Reqistration request has no tenant
				->
		"""
		registration_token = request.match_info["registration_token"]
		token_data = await self.RegistrationService.get_registration_token(registration_token)

		headers = request.headers
		authorization_bytes = bytes(headers.get("Authorization", ""), "ascii")
		register_info['request_authorization'] = authorization_bytes

		req_data = await request.read()

		# decrypt request body
		if self.RegistrationEncrypted:
			req_data = asab.web.webcrypto.aes_gcm_decrypt(
				register_info['key'],
				req_data  # , register_token.encode('ascii')
			)
		try:
			data = json.loads(req_data)
		except json.decoder.JSONDecodeError:
			return aiohttp.web.HTTPBadRequest(reason="Invalid json.")

		# fill register_info
		# TODO: Validations !!!
		register_info['request'] = data
		# TODO: If email has to be confirmed, for that here

		# register
		result = await self.CredentialsService.register_credentials(register_info)
		if result is None:
			return asab.web.rest.json_response(request, {'result': 'FAILED'})
		else:
			self.Registrations.pop(register_token)
			return asab.web.rest.json_response(request, {'result': 'OK'})
