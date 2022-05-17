import logging

import asab.web.rest

from ...decorators import access_control

###

L = logging.getLogger(__name__)

###


result_code = {
	"OK": 200,
	"TENANT-NOT-SPECIFIED": 400,
	"NOT-AUTHORIZED": 401
}


class RBACHandler(object):
	"""
	Implements check whether the user is authorized to access the given resource or not.
	"""

	def __init__(self, app, rbac_svc):
		self.RBACService = rbac_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get('/rbac/{resources}', self.rbac)
		web_app.router.add_get('/rbac/{tenant}/{resources}', self.rbac)

	@access_control()
	async def rbac(self, request, *, tenant):
		# Obtain the resources and credentials ID
		requested_resources = request.match_info["resources"].split('+')

		result = self.RBACService.has_resource_access(request.Session.Authorization.authz, tenant, requested_resources)

		return asab.web.rest.json_response(
			request,
			data={"result": result},
			reason=result_code[result]
		)
