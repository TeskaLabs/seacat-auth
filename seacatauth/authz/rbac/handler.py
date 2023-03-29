import logging

import asab.web.rest

from ...decorators import access_control
from ...exceptions import TenantNotSpecifiedError

###

L = logging.getLogger(__name__)

###


class RBACHandler(object):
	"""
	Implements check whether the user is authorized to access the given resource or not.
	"""

	def __init__(self, app, rbac_svc):
		self.RBACService = rbac_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/rbac/{resources}", self.rbac)
		web_app.router.add_get("/rbac/{tenant}/{resources}", self.rbac)

	@access_control()
	async def rbac(self, request, *, tenant):
		"""
		Validate the current credentials' access to requested resources

		Multiple resources must be separated by `+`.
		"""
		# Obtain the resources and credentials ID
		requested_resources = request.match_info["resources"].split('+')

		try:
			if self.RBACService.has_resource_access(request.Session.Authorization.Authz, tenant, requested_resources):
				return asab.web.rest.json_response(
					request,
					data={"result": "OK"},
					reason=200
				)
			else:
				return asab.web.rest.json_response(
					request,
					data={"result": "NOT-AUTHORIZED"},
					reason=401
				)
		except TenantNotSpecifiedError:
			return asab.web.rest.json_response(
				request,
				data={"result": "TENANT-NOT-SPECIFIED"},
				reason=400
			)
