import logging

import asab.web.rest

#

L = logging.getLogger(__name__)

#


class PublicKeysHandler(object):
	"""
	Public keys

	---
	tags: ["OAuth 2.0 / OpenID Connect"]
	"""

	def __init__(self, app, oidc_svc):
		self.App = app

		self.OpenIdConnectService = oidc_svc

		web_app = app.WebContainer.WebApp
		# It is a convention to expose the JWKS at /.well-known/jwks.json
		web_app.router.add_get("/.well-known/jwks.json", self.public_keys)
		web_app.router.add_get(self.OpenIdConnectService.JwksPath, self.public_keys)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get("/.well-known/jwks.json", self.public_keys)
		web_app_public.router.add_get(self.OpenIdConnectService.JwksPath, self.public_keys)


	async def public_keys(self, request):
		"""
		JSON Web Key Sets

		---
		parameters:
		-	name: format
			in: query
			description: Server key format
			required: false
			schema:
				type: boolean
				enum: ["pem", "jwk"]
		"""
		# TODO: Multiple key support
		public_key = self.OpenIdConnectService.PrivateKey.public()
		key_format = request.query.get("format", "jwk")

		if key_format == "jwk":
			# Export as JWK object
			data = {"keys": [
				public_key.export_public(as_dict=True)
			]}
		elif key_format == "pem":
			# Export as PEM
			data = {
				public_key.get("kid"): public_key.export_to_pem().decode("ascii")
			}
		else:
			return asab.web.rest.json_response(
				request,
				status=400,
				data={
					"result": "FAILED",
					"message": "Invalid 'format' value: {}".format(key_format),
				},
			)

		return asab.web.rest.json_response(request, data)
