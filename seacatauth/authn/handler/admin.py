import logging

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

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/admin/credentials/{credentials_id}/authn-methods", self.list_authn_methods)
		web_app.router.add_get("/admin/credentials/{credentials_id}/authn-methods/{method_type}", self.list_authn_methods_by_type)
		web_app.router.add_get("/admin/credentials/{credentials_id}/authn-methods/{method_type}/{method_id}", self.get_authn_method_by_id)
		web_app.router.add_delete("/admin/credentials/{credentials_id}/authn-methods/{method_type}/{method_id}", self.delete_authn_method_by_id)


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

		methods = []
		for provider in self.AuthenticationService.AuthnMethodProviders.values():
			async for method in provider.iterate_authn_methods(credentials_id):
				methods.append(method)

		return asab.web.rest.json_response(request, {
			"data": methods,
			"count": len(methods),
		})


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require_superuser
	async def list_authn_methods_by_type(self, request):
		"""
		List authentication methods of given type for given credentials
		"""
		credentials_id = request.match_info["credentials_id"]
		try:
			await self.CredentialsService.get(credentials_id, include=["__password"])
		except exceptions.CredentialsNotFoundError as e:
			return e.json_response(request)

		methods = []
		provider = self.AuthenticationService.AuthnMethodProviders.get(request.match_info["method_type"])
		if provider is None:
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)
		async for method in provider.iterate_authn_methods(credentials_id):
			methods.append(method)

		return asab.web.rest.json_response(request, {
			"data": methods,
			"count": len(methods),
		})


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require_superuser
	async def get_authn_method_by_id(self, request):
		"""
		Get authentication method by ID for given credentials.
		Singleton methods use method_id = "-".
		"""
		credentials_id = request.match_info["credentials_id"]
		provider = self.AuthenticationService.AuthnMethodProviders.get(request.match_info["method_type"])
		if provider is None:
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)
		method_id = request.match_info["method_id"]
		if method_id == "-":
			method_id = None
		try:
			method = await provider.get_authn_method(credentials_id, method_id)
		except KeyError:
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)
		return asab.web.rest.json_response(request, method)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require_superuser
	async def delete_authn_method_by_id(self, request):
		"""
		Delete authentication method by ID for given credentials.
		Singleton methods use method_id = "-".
		"""
		credentials_id = request.match_info["credentials_id"]
		provider = self.AuthenticationService.AuthnMethodProviders.get(request.match_info["method_type"])
		if provider is None:
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)
		if "delete" not in provider.SupportedActions:
			return asab.web.rest.json_response(request, {"result": "NOT-ALLOWED"}, status=405)
		method_id = request.match_info["method_id"]
		if method_id == "-":
			method_id = None
		try:
			method = await provider.delete_authn_method(credentials_id, method_id)
		except KeyError:
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)
		return asab.web.rest.json_response(request, method)
