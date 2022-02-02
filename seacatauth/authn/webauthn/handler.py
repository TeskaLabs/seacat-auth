import logging

import asab.web
import asab.web.rest

from ...decorators import access_control

#

L = logging.getLogger(__name__)

#


class WebAuthnHandler(object):

	def __init__(self, app, otp_svc):
		self.CredentialsService = app.get_service('seacatauth.CredentialsService')
		self.OTPService = otp_svc
		web_app_public = app.PublicWebContainer.WebApp

		web_app = app.WebContainer.WebApp
		web_app.router.add_get('/public/webauthn', self.get_totp)
		web_app.router.add_post('/public/set-webauthn', self.set_totp)
		web_app.router.add_put('/public/unset-totp', self.unset_totp)

		# Public endpoints
		web_app_public.router.add_get('/public/totp', self.get_totp)
		web_app_public.router.add_put('/public/set-totp', self.set_totp)
		web_app_public.router.add_put('/public/unset-totp', self.unset_totp)

	@access_control()
	async def get_totp(self, request, *, credentials_id):
		"""
		Returns the status of TOTP setting.
		If not activated, it also generates and returns a new TOTP secret.

		{
			"publicKey": {
				"challenge": "ROexfyIEVsi563ZPB7S9gbf8/h/6atohDJr8sJvJ3Oo=",
				"rp": {
					"name": "webauthn.io",
					"id": "webauthn.io"
				},
				"user": {
					"name": "example",
					"displayName": "example",
					"id": "vsQRAAAAAAAAAA=="
				},
				"pubKeyCredParams": [
					{
						"type": "public-key",
						"alg": -7
					},
					{
						"type": "public-key",
						"alg": -35
					},
					{
						"type": "public-key",
						"alg": -36
					},
					{
						"type": "public-key",
						"alg": -257
					},
					{
						"type": "public-key",
						"alg": -258
					},
					{
						"type": "public-key",
						"alg": -259
					},
					{
						"type": "public-key",
						"alg": -37
					},
					{
						"type": "public-key",
						"alg": -38
					},
					{
						"type": "public-key",
						"alg": -39
					},
					{
						"type": "public-key",
						"alg": -8
					}
				],
				"authenticatorSelection": {
					"requireResidentKey": false,
					"userVerification": "discouraged"
				},
				"timeout": 60000,
				"extensions": {
					"txAuthSimple": ""
				},
				"attestation": "none"
			}
		}
		"""
		response = await self.OTPService.get_totp(request.Session, credentials_id)
		return asab.web.rest.json_response(request, response)

	@asab.web.rest.json_schema_handler({
		'type': 'object',
		'required': ['otp'],
		'properties': {
			'otp': {'type': 'string'}
		}
	})
	@access_control()
	async def set_totp(self, request, *, credentials_id, json_data):
		"""
		Activates TOTP for the current user, provided that a TOTP secret is already set.
		"""
		otp = json_data.get("otp")
		response = await self.OTPService.set_totp(request.Session, credentials_id, otp)
		return asab.web.rest.json_response(request, response)


	@access_control()
	async def unset_totp(self, request, *, credentials_id):
		"""
		Deactivates TOTP for the current user and erases the secret.
		"""
		response = await self.OTPService.unset_totp(credentials_id)
		return asab.web.rest.json_response(request, response)
