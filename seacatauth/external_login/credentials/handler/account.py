import logging
import asab
import asab.web.rest
import asab.web.tenant

from ..service import ExternalCredentialsService
from ...exceptions import ExternalAccountNotFoundError


L = logging.getLogger(__name__)


class ExternalLoginAccountHandler(object):
	"""
	Manage my external login accounts

	---
	tags: ["Account - External login"]
	"""

	def __init__(self, app, external_credentials_svc: ExternalCredentialsService):
		self.App = app
		self.ExternalCredentialsService = external_credentials_svc
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/account/ext-login", self.list_my_ext_credentials)
		web_app.router.add_get("/account/ext-login/{provider_type}/{subject_id}", self.get_my_ext_credentials)
		web_app.router.add_delete("/account/ext-login/{provider_type}/{subject_id}", self.remove_my_ext_credentials)


	@asab.web.tenant.allow_no_tenant
	async def list_my_ext_credentials(self, request):
		"""
		List the current user's external login accounts
		"""
		authz = asab.contextvars.Authz.get()
		data = await self.ExternalCredentialsService.list_ext_credentials(authz.CredentialsId)
		return asab.web.rest.json_response(request, {
			"data": data,
			"count": len(data),
		})


	@asab.web.tenant.allow_no_tenant
	async def get_my_ext_credentials(self, request):
		"""
		Get the current user's external login credentials detail
		"""
		provider_type = request.match_info["provider_type"]
		subject_id = request.match_info["subject_id"]
		try:
			data = await self.ExternalCredentialsService.get_ext_credentials(
				provider_type, subject_id)
			return asab.web.rest.json_response(request, data)
		except ExternalAccountNotFoundError:
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)


	@asab.web.tenant.allow_no_tenant
	async def remove_my_ext_credentials(self, request):
		"""
		Remove the current user's external login account
		"""
		provider_type = request.match_info["provider_type"]
		subject_id = request.match_info["subject_id"]
		try:
			await self.ExternalCredentialsService.delete_ext_credentials(
				provider_type, subject_id)
			return asab.web.rest.json_response(request, {"result": "OK"})
		except ExternalAccountNotFoundError:
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)
