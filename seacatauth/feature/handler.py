import logging
import asab
import asab.web.rest
import asab.web.auth
import asab.web.tenant


L = logging.getLogger(__name__)


class FeatureHandler(object):
	"""
	Login and registration features

	---
	tags: ["Login and authentication"]
	"""

	def __init__(self, app, feture_svc):
		self.FeatureService = feture_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/public/features", self.get_features)
		web_app.router.add_get("/account/features", self.get_features)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get("/public/features", self.get_features)


	@asab.web.auth.noauth
	@asab.web.tenant.allow_no_tenant
	async def get_features(self, request):
		"""
		Get public login and registration features
		"""
		features = await self.FeatureService.get_features()
		return asab.web.rest.json_response(request, data=features)
