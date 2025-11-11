import logging
import asab.web
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.contextvars

from .... import exceptions


L = logging.getLogger(__name__)


class OTPAdminHandler(object):
	"""
	Manage target user's TOTP

	---
	tags: ["One-Time PIN (TOTP)"]
	"""

	def __init__(self, app, otp_svc):
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.OTPService = otp_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/admin/credentials/{credentials_id}/authn/totp", self.get_totp_status)
		web_app.router.add_delete("/admin/credentials/{credentials_id}/authn/totp", self.deactivate_totp)


	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
	async def get_totp_status(self, request):
		"""
		See if target credentials have TOTP activated
		"""
		credentials_id = request.match_info["credentials_id"]
		try:
			has_activated_totp = await self.OTPService.has_activated_totp(credentials_id)
		except exceptions.CredentialsNotFoundError as e:
			return e.json_response(request)

		return asab.web.rest.json_response(request, {"active": has_activated_totp})


	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
	async def deactivate_totp(self, request):
		"""
		Deactivate TOTP for target credentials
		"""
		credentials_id = request.match_info["credentials_id"]
		try:
			await self.OTPService.deactivate_totp(credentials_id)
		except exceptions.TOTPDeactivationError:
			return asab.web.rest.json_response(request, {"result": "FAILED"}, status=400)
		except exceptions.CredentialsNotFoundError as e:
			return e.json_response(request)

		return asab.web.rest.json_response(request, {"result": "OK"})
