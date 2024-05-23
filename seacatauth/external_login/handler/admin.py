import logging
import urllib.parse

import aiohttp.web
import asab
import asab.web.rest

from seacatauth.external_login.service import ExternalLoginService
from seacatauth import generic, exceptions
from seacatauth.decorators import access_control

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
		data = await self.ExternalLoginService.list_accounts(credentials_id)
		return asab.web.rest.json_response(request, data)


	@access_control("authz:superuser")
	async def get_external_account(self, request):
		"""
		Get external login credentials detail
		"""
		provider_type = request.match_info["provider_type"]
		subject = request.match_info["sub"]
		data = await self.ExternalLoginService.get_account(provider_type, subject)
		return asab.web.rest.json_response(request, data)


	@access_control("authz:superuser")
	async def remove_external_account(self, request):
		"""
		Remove external login credentials
		"""
		provider_type = request.match_info["provider_type"]
		subject = request.match_info["sub"]
		await self.ExternalLoginService.remove_account(provider_type, subject)
		return asab.web.rest.json_response(request, {"result": "OK"})
