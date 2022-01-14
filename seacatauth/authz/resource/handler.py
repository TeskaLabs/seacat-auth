import logging

import asab
import asab.web.rest

from seacatauth.decorators import access_control

#

L = logging.getLogger(__name__)

#


class ResourceHandler(object):
	def __init__(self, app, rbac_svc):
		self.RBACService = rbac_svc
		self.ResourceService = app.get_service("seacatauth.ResourceService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/resource", self.list)
		web_app.router.add_get("/resource/{resource_id}", self.get)
		web_app.router.add_put("/resource/{resource_id}", self.create)

	async def list(self, request):
		# TODO: filtering by module
		page = int(request.query.get('p', 1)) - 1
		limit = int(request.query.get('i', 10))
		resources = await self.ResourceService.list(page, limit)
		return asab.web.rest.json_response(request, resources)

	async def get(self, request):
		resource_id = request.match_info["resource_id"]
		result = await self.ResourceService.get(resource_id)
		return asab.web.rest.json_response(
			request, result
		)

	@access_control("authz:superuser")
	async def create(self, request):
		resource_id = request.match_info["resource_id"]
		data = await self.ResourceService.create(resource_id)
		status = 200 if data["result"] == "OK" else 400
		return asab.web.rest.json_response(
			request,
			status=status,
			data=data,
		)
