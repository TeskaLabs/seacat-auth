import asab.web.rest
import asab.contextvars
import asab.web.tenant


class RBACHandler(object):
	"""
	Resource-based access control

	---
	tags: ["Resources"]
	"""

	def __init__(self, app, rbac_svc):
		self.RBACService = rbac_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/rbac/{resources}", self.rbac)
		web_app.router.add_get("/rbac/{tenant}/{resources}", self.rbac)


	@asab.web.tenant.allow_no_tenant
	async def rbac(self, request):
		"""
		Verify whether the current session is authorized to access requested resources

		Multiple resources must be separated by `+`.
		"""
		# Obtain the resources and credentials ID
		requested_resources = request.match_info["resources"].split('+')

		authz = asab.contextvars.Authz.get()
		tenant = asab.contextvars.Tenant.get()

		if self.RBACService.has_resource_access(authz._resources(), tenant, requested_resources):
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
