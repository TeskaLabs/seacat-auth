import logging
import asab
import asab.web.rest
import asab.web.tenant

from ..service import ExternalLoginService
from ..exceptions import ExternalAccountNotFoundError


L = logging.getLogger(__name__)


class ExternalLoginAccountHandler(object):
	"""
	Manage my external login accounts

	---
	tags: ["Account - External login"]
	"""

	def __init__(self, app, external_login_svc: ExternalLoginService):
		self.App = app
		self.ExternalLoginService = external_login_svc
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/account/ext-login", self.list_my_external_accounts)
		web_app.router.add_get("/account/ext-login/{provider_type}/{subject_id}", self.get_my_external_account)
		web_app.router.add_delete("/account/ext-login/{provider_type}/{subject_id}", self.remove_my_external_account)


	@asab.web.tenant.allow_no_tenant
	async def list_my_external_accounts(self, request):
		"""
		List the current user's external login accounts
		"""
		authz = asab.contextvars.Authz.get()
		data = await self.ExternalLoginService.list_external_accounts(authz.CredentialsId)
		return asab.web.rest.json_response(request, data)


	@asab.web.tenant.allow_no_tenant
	async def get_my_external_account(self, request):
		"""
		Get the current user's external login credentials detail
		"""
		authz = asab.contextvars.Authz.get()
		provider_type = request.match_info["provider_type"]
		subject_id = request.match_info["subject_id"]
		try:
			data = await self.ExternalLoginService.get_external_account(
				provider_type, subject_id, credentials_id=authz.CredentialsId)
			return asab.web.rest.json_response(request, data)
		except ExternalAccountNotFoundError:
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)


	@asab.web.tenant.allow_no_tenant
	async def remove_my_external_account(self, request):
		"""
		Remove the current user's external login account
		"""
		authz = asab.contextvars.Authz.get()
		provider_type = request.match_info["provider_type"]
		subject_id = request.match_info["subject_id"]
		try:
			await self.ExternalLoginService.remove_external_account(
				provider_type, subject_id, credentials_id=authz.CredentialsId)
			return asab.web.rest.json_response(request, {"result": "OK"})
		except ExternalAccountNotFoundError:
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)
