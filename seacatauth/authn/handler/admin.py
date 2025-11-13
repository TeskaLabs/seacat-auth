import logging
import asab
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.exceptions
import asab.contextvars
import aiohttp.web

from ... import exceptions, AuditLogger
from ...models.const import ResourceId
from ...openidconnect.utils import AUTHORIZE_PARAMETERS
from .. import schema


L = logging.getLogger(__name__)


class AuthenticationAdminHandler(object):
	"""
	Login and authentication

	---
	tags: ["Login and authentication"]
	"""

	def __init__(self, app, authn_svc):
		self.App = app
		self.AuthenticationService = authn_svc
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/admin/credentials/{credentials_id}/authn", self.list_authn_methods)


	@asab.web.tenant.allow_no_tenant
	async def list_authn_methods(self, request):
		"""
		"""
		ext_credentials_svc = self.App.get_service("seacatauth.ExternalCredentialsService")
		webauthn_svc = self.App.get_service("seacatauth.WebAuthnService")
		otp_svc = self.App.get_service("seacatauth.OTPService")

		credentials_id = request.match_info["credentials_id"]
		try:
			credentials = await self.CredentialsService.get(credentials_id, include=["__password"])
		except exceptions.CredentialsNotFoundError as e:
			return e.json_response(request)

		methods = []
		if credentials.get("__password") is not None:
			methods.append({
				"_id": "password",
				"type": "password",
			})


