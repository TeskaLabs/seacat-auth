import base64
import json
import logging

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
		web_app.router.add_put('/public/webauthn/register', self.register)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get('/public/webauthn/register-options', self.get_registration_options)
		web_app_public.router.add_put('/public/webauthn/register', self.register)


	@access_control()
	async def get_registration_options(self, request, *, credentials_id):
		response = await self.WebAuthnService.get_registration_options(credentials_id)
		return asab.web.rest.json_response(request, response)

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
	async def register(self, request, *, json_data, credentials_id):
		import pprint
		L.warning(f"\n🌻JSON DATA {pprint.pformat(json_data)}")
		# Verify that the request CID matches the session CID
		assert credentials_id == base64.urlsafe_b64decode(json_data["id"].encode("ascii") + b"==").decode()

		# The value SHOULD be a member of PublicKeyCredentialType but client platforms MUST ignore unknown values,
		# ignoring any PublicKeyCredentialParameters with an unknown type.
		# Currently one credential type is defined, namely "public-key".
		assert json_data["type"] == "public-key"

		# Parse the client data
		client_data = json.loads(
			base64.urlsafe_b64decode(
				json_data["response"]["clientDataJSON"].encode("ascii") + b"=="
			).decode()
		)
		attestation_object = base64.urlsafe_b64decode(
			client_data["attestationObject"].encode("ascii") + b"=="
		).decode()

		response = await self.WebAuthnService.register(credentials_id, client_data, attestation_object)
		return asab.web.rest.json_response(request, response)
