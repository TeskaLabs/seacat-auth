import base64
import logging

import aiohttp.web
import asab.web
import asab.web.rest

from ...decorators import access_control

#

L = logging.getLogger(__name__)

#


class WebAuthnHandler(object):

	"""
	Example implementation:
	https://github.com/pyauth/pywarp/blob/master/pywarp/rp.py
	"""

	def __init__(self, app, webauthn_svc):
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.WebAuthnService = webauthn_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get('/public/webauthn/register-options', self.get_registration_options)
		web_app.router.add_put('/public/webauthn/register', self.register_credential)
		web_app.router.add_delete('/public/webauthn', self.remove_credential)
		web_app.router.add_delete('/public/webauthn/{wacid}', self.remove_credential)
		web_app.router.add_put('/public/webauthn/{wacid}', self.update_credential)
		web_app.router.add_get('/public/webauthn', self.list_credentials)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get('/public/webauthn/register-options', self.get_registration_options)
		web_app_public.router.add_put('/public/webauthn/register', self.register_credential)
		web_app_public.router.add_delete('/public/webauthn', self.remove_credential)
		web_app_public.router.add_delete('/public/webauthn/{wacid}', self.remove_credential)
		web_app_public.router.add_put('/public/webauthn/{wacid}', self.update_credential)
		web_app_public.router.add_get('/public/webauthn', self.list_credentials)


	@access_control()
	async def get_registration_options(self, request):
		options = await self.WebAuthnService.get_registration_options(request.Session)
		return aiohttp.web.Response(body=options, content_type="application/json")
		# return asab.web.rest.json_response(request, options)

	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": [
			"id",
			"rawId",
			"response",
			"type",
		],
		"properties": {
			"id": {
				# Credentials ID
				"type": "string"
			},
			"rawId": {
				# The ID again, but in binary form
				"type": "string"
			},
			"response": {
				# The actual WebAuthn login data
				"type": "object",
				"required": [
					"clientDataJSON",
					"attestationObject",
				],
				"properties": {
					"clientDataJSON": {"type": "string"},
					"attestationObject": {"type": "string"},
				}
			},
			"type": {
				"type": "string",
				"enum": ["public-key"],
			},
		}
	})
	@access_control()
	async def register_credential(self, request, *, json_data):
		response = await self.WebAuthnService.register_credential(request.Session, public_key_credential=json_data)
		return asab.web.rest.json_response(
			request, response,
			status=200 if response["result"] == "OK" else 400
		)

	@access_control()
	async def list_credentials(self, request, *, credentials_id):
		wa_credentials = []
		for credential in await self.WebAuthnService.get_webauthn_credentials_by_user(credentials_id):
			wa_credentials.append({
				"id": base64.urlsafe_b64encode(credential["_id"]).decode("ascii").rstrip("="),
				"name": credential["name"],
				"sign_count": credential["sc"],
			})

		return asab.web.rest.json_response(request, {
			"result": "OK",
			"data": wa_credentials,
			"count": len(wa_credentials),
		})

	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": [
			"name",
		],
		"properties": {
			"name": {
				"type": "string",
				"pattern": "^[a-z][a-z0-9._-]{0,128}[a-z0-9]$"
			},
		}
	})
	@access_control()
	async def update_credential(self, request, *, json_data):
		wacid = base64.urlsafe_b64decode(request.match_info["wacid"].encode("ascii") + b"==")
		await self.WebAuthnService.update_webauthn_credential(wacid, name=json_data["name"])
		return asab.web.rest.json_response(
			request, {"result": "OK"}
		)

	@access_control()
	async def remove_credential(self, request):
		wacid = base64.urlsafe_b64decode(request.match_info["wacid"].encode("ascii") + b"==")
		await self.WebAuthnService.delete_webauthn_credential(wacid)
		return asab.web.rest.json_response(
			request, {"result": "OK"}
		)
