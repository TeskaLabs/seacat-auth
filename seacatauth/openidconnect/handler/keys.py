import logging

import asab.web.rest

#

L = logging.getLogger(__name__)

#


class KeysHandler(object):


	def __init__(self, app, oidc_svc):
		self.App = app

		self.OpenIdConnectService = oidc_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/openidconnect/keys", self.keys)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get("/openidconnect/keys", self.keys)


	async def keys(self, request):
		"""
		Return public keys that the client can use for token verification.

		Specify ?pem in query to return the keys in PEM format.
		"""
		# TODO: Multiple key support
		public_key = self.OpenIdConnectService.PrivateKey.public()

		if request.query.get("pem") is not None:
			# Export as PEM
			data = {
				public_key.get("kid"): public_key.export_to_pem().decode("ascii")
			}
		else:
			# Export as JWK object
			data = {"keys": [
				public_key.export_public(as_dict=True)
			]}

		return asab.web.rest.json_response(request, data)
