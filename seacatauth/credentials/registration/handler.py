import json
import secrets
import logging

import aiohttp
import aiohttp.web

import asab
import asab.web.rest
import asab.web.webcrypto

#

L = logging.getLogger(__name__)

#


class RegistrationHandler(object):

	def __init__(self, app, registration_svc):
		self.RegistrationService = registration_svc

		self.SessionService = app.get_service("seacatauth.SessionService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.AuditService = app.get_service('seacatauth.AuditService')

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/{tenant}/register/invite", self.create_invite)
		web_app.router.add_get("/public/register", self.register_get)
		web_app.router.add_get("/public/invitation/{register_token}", self.register_with_invite_get)
		web_app.router.add_post("/public/register/{register_token}", self.register_post)

		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get("/public/register", self.register_get)
		web_app_public.router.add_get("/public/invitation/{register_token}", self.register_with_invite_get)
		web_app_public.router.add_post("/public/register/{register_token}", self.register_post)

	async def register_get(self, request):
		# TODO: Limit a total number of active registration
		# TODO: Limit a number of active registration from a single IP
		register_token = secrets.token_urlsafe()
		key = secrets.token_bytes(256 // 8)
		register_info = {
			'timestamp': self.CredentialsService.App.time(),
			"features": [
				"email",
				"password",
				"tenant",
			]
			# TODO: add an IP from where registration is made (including proxy)
		}
		if self.RegistrationEncrypted:
			register_info['key'] = key

		self.Registrations[register_token] = register_info

		result = {
			"register_token": register_token,
			'features': register_info['features'],
		}

		if self.RegistrationEncrypted:
			result["key"] = asab.web.webcrypto.aes_gcm_generate_key(key),

		return asab.web.rest.json_response(request, result)

	async def register_with_invite_get(self, request):
		# TODO: Limit a total number of active registration
		# TODO: Limit a number of active registration from a single IP
		register_token = request.match_info["register_token"]
		register_info = self.Registrations.get(register_token)
		if register_info is None:
			return aiohttp.web.HTTPBadRequest(reason="Invalid register_token.")

		result = {
			"register_token": register_token,
			'features': register_info['features'],
			'tenant': register_info['tenant'],
		}

		if self.RegistrationEncrypted:
			result['key'] = asab.web.webcrypto.aes_gcm_generate_key(register_info["key"]),

		return asab.web.rest.json_response(request, result)

	async def create_invite(self, request):
		# TODO: Limit a total number of active invites
		# TODO: Limit a number of active registration from a single invites
		tenant = request.match_info["tenant"]

		register_token = secrets.token_urlsafe()
		key = secrets.token_bytes(256 // 8)
		register_info = {
			'timestamp': self.CredentialsService.App.time(),
			'key': key,
			'tenant': tenant,
			"features": [
				"email",
				"password",
			]
			# TODO: add an IP from where invite is made (including proxy)
		}
		self.Registrations[register_token] = register_info
		result = {
			"register_token": register_token,
		}
		return asab.web.rest.json_response(request, result)

	async def register_post(self, request):
		register_token = request.match_info["register_token"]
		register_info = self.Registrations.get(register_token)
		if register_info is None:
			return aiohttp.web.HTTPBadRequest(reason="Invalid register_token.")

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
