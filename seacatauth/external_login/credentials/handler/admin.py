import logging
import asab
import asab.web.rest
import asab.web.auth
import asab.web.tenant

from ..service import ExternalCredentialsService
from ...exceptions import ExternalAccountNotFoundError


L = logging.getLogger(__name__)


class ExternalCredentialsAdminHandler(object):
	"""
	Administrate external login accounts

	---
	tags: ["Admin - External login"]
	"""

	def __init__(self, app, external_credentials_svc: ExternalCredentialsService):
		self.App = app
		self.ExternalCredentialsService = external_credentials_svc
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/admin/ext-login/{credentials_id}", self.list_ext_credentials)
		web_app.router.add_get("/admin/ext-login/{provider_type}/{sub}", self.get_ext_credentials)
		web_app.router.add_delete("/admin/ext-login/{provider_type}/{sub}", self.remove_ext_credentials)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require_superuser
	async def list_ext_credentials(self, request):
		"""
		List user's external login accounts
		"""
		credentials_id = request.match_info["credentials_id"]
		data = await self.ExternalCredentialsService.list_ext_credentials(credentials_id)
		return asab.web.rest.json_response(request, data)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require_superuser
	async def get_ext_credentials(self, request):
		"""
		Get external login account detail
		"""
		provider_type = request.match_info["provider_type"]
		subject = request.match_info["sub"]
		try:
			data = await self.ExternalCredentialsService.get_ext_credentials(provider_type, subject)
			return asab.web.rest.json_response(request, data)
		except ExternalAccountNotFoundError:
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require_superuser
	async def remove_ext_credentials(self, request):
		"""
		Remove external login account
		"""
		provider_type = request.match_info["provider_type"]
		subject = request.match_info["sub"]
		try:
			await self.ExternalCredentialsService.remove_ext_credentials(provider_type, subject)
		except ExternalAccountNotFoundError:
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)
		return asab.web.rest.json_response(request, {"result": "OK"})
