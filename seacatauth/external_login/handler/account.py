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
		web_app.router.add_get("/account/ext-login/{provider_type}/add", self.add_external_account)
		web_app.router.add_get("/account/ext-login", self.list_my_external_accounts)
		web_app.router.add_get("/account/ext-login/{provider_type}/{sub}", self.get_my_external_account)
		web_app.router.add_delete("/account/ext-login/{provider_type}/{sub}", self.remove_my_external_account)


	async def add_external_account(self, request):
		"""
		Initialize adding an external account into the current user's credentials.
		Navigable endpoint, redirects to external login page.
		"""
		redirect_uri = request.query.get("redirect_uri")
		provider_type = request.match_info["provider_type"]
		authorization_url = await self.ExternalLoginService.add_external_account_initialize(provider_type, redirect_uri)
		return aiohttp.web.HTTPFound(location=authorization_url)


	async def list_my_external_accounts(self, request):
		"""
		List the current user's external login accounts
		"""
		data = await self.ExternalLoginService.list_accounts(request.Session.Credentials.Id)
		return asab.web.rest.json_response(request, data)


	async def get_my_external_account(self, request):
		"""
		Get the current user's external login credentials detail
		"""
		provider_type = request.match_info["provider_type"]
		subject = request.match_info["sub"]
		data = await self.ExternalLoginService.get_account(
			provider_type, subject, credentials_id=request.Session.Credentials.Id)
		return asab.web.rest.json_response(request, data)


	async def remove_my_external_account(self, request):
		"""
		List the current user's external login accounts
		"""
		provider_type = request.match_info["provider_type"]
		subject = request.match_info["sub"]
		await self.ExternalLoginService.remove_account(
			provider_type, subject, credentials_id=request.Session.Credentials.Id)
		return asab.web.rest.json_response(request, {"result": "OK"})
