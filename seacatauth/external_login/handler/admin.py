import logging

import asab
import asab.web.rest

from ..service import ExternalLoginService
from ...decorators import access_control
from ..exceptions import ExternalAccountNotFoundError

#

L = logging.getLogger(__name__)

#


class ExternalLoginAdminHandler(object):
	"""
	Administrate external login accounts

	---
	tags: ["Admin - External login"]
	"""

	def __init__(self, app, external_login_svc: ExternalLoginService):
		self.App = app
		self.ExternalLoginService = external_login_svc
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/admin/ext-login/{credentials_id}", self.list_external_accounts)
		web_app.router.add_get("/admin/ext-login/{provider_type}/{sub}", self.get_external_account)
		web_app.router.add_delete("/admin/ext-login/{provider_type}/{sub}", self.remove_external_account)


	@access_control("authz:superuser")
	async def list_external_accounts(self, request):
		"""
		List user's external login credentials
		"""
		credentials_id = request.match_info["credentials_id"]
		data = await self.ExternalLoginService.list_external_accounts(credentials_id)
		return asab.web.rest.json_response(request, data)


	@access_control("authz:superuser")
	async def get_external_account(self, request):
		"""
		Get external login credentials detail
		"""
		provider_type = request.match_info["provider_type"]
		subject = request.match_info["sub"]
		try:
			data = await self.ExternalLoginService.get_external_account(provider_type, subject)
			return asab.web.rest.json_response(request, data)
		except ExternalAccountNotFoundError:
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)


	@access_control("authz:superuser")
	async def remove_external_account(self, request):
		"""
		Remove external login credentials
		"""
		provider_type = request.match_info["provider_type"]
		subject = request.match_info["sub"]
		try:
			await self.ExternalLoginService.remove_external_account(provider_type, subject)
		except ExternalAccountNotFoundError:
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)
		return asab.web.rest.json_response(request, {"result": "OK"})
