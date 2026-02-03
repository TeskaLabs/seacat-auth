import logging
import typing

import asab
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.exceptions
import asab.contextvars

from ... import exceptions


L = logging.getLogger(__name__)


class AuthenticationAdminHandler(object):
	"""
	Authentication method management

	---
	tags: ["Login and authentication"]
	"""

	def __init__(self, app, authn_svc):
		self.App = app
		self.AuthenticationService = authn_svc
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.AuthnMethodProviders = {}

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/admin/credentials/{credentials_id}/authn-methods", self.list_authn_methods)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require_superuser
	async def list_authn_methods(self, request):
		"""
		List authentication methods for given credentials
		"""
		credentials_id = request.match_info["credentials_id"]
		try:
			await self.CredentialsService.get(credentials_id, include=["__password"])
		except exceptions.CredentialsNotFoundError as e:
			return e.json_response(request)

		providers = [
			self.App.get_service("seacatauth.ChangePasswordService"),
			self.App.get_service("seacatauth.OTPService"),
			self.App.get_service("seacatauth.WebAuthnService"),
			self.App.get_service("seacatauth.ExternalCredentialsService"),
		]

		methods = []
		for provider in providers:
			if provider is None:
				continue
			async for method in provider.iterate_authn_methods(credentials_id):
				methods.append(method)

		return asab.web.rest.json_response(request, {
			"data": methods,
			"count": len(methods),
		})
