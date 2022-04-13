import base64
import json
import logging
import pprint

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

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get('/public/webauthn/register-options', self.get_registration_options)
		web_app_public.router.add_put('/public/webauthn/register', self.register_credential)
		web_app_public.router.add_delete('/public/webauthn', self.remove_credential)


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
	async def remove_credential(self, request, *, credentials_id):
		response = await self.WebAuthnService.delete_webauthn_credentials_by_user(credentials_id)
		# response = await self.WebAuthnService.delete_webauthn_credential(webauthn_credential_id)
		return asab.web.rest.json_response(
			request, response,
			status={"result": "OK"}
		)
