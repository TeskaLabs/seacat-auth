import logging

import asab.web
import asab.web.rest

from ..decorators import access_control

#

L = logging.getLogger(__name__)

#


class OTPHandler(object):

	def __init__(self, app, otp_svc):
		self.CredentialsService = app.get_service('seacatauth.CredentialsService')
		self.OTPService = otp_svc
		web_app_public = app.PublicWebContainer.WebApp

		web_app = app.WebContainer.WebApp
		web_app.router.add_get('/public/totp', self.get_totp)
		web_app.router.add_put('/public/set-totp', self.set_totp)
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
