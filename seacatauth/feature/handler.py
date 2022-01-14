import logging

import asab
import asab.web.rest

#

L = logging.getLogger(__name__)

#


class FeatureHandler(object):

	def __init__(self, app, feture_svc):
		self.FeatureService = feture_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/public/features", self.get_features)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get("/public/features", self.get_features)

	async def get_features(self, request):
		features = await self.FeatureService.get_features()
		response = {
			"data": features,
			"result": "OK",
		}
		return asab.web.rest.json_response(request, response)
