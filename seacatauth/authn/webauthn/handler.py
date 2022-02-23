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
		web_app.router.add_get('/public/webauthn-register-options', self.get_registration_options)
		web_app.router.add_put('/public/webauthn-register', self.register)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get('/public/webauthn-register-options', self.get_registration_options)
		web_app_public.router.add_put('/public/webauthn-register', self.register)


	@access_control()
	async def get_registration_options(self, request, *, credentials_id):
		response = await self.WebAuthnService.get_registration_options(credentials_id)
		return asab.web.rest.json_response(request, response)

	@access_control()
	async def register(self, request, *, json_data, credentials_id):
		# TODO: Get attestation object
		response = await self.WebAuthnService.register(credentials_id, json_data)
		return asab.web.rest.json_response(request, response)
