import logging
import asab.web
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.contextvars

from .. import exceptions
from . import schema


L = logging.getLogger(__name__)


class OTPHandler(object):
	"""
	Manage TOTP

	---
	tags: ["One-Time PIN (TOTP)"]
	"""

	def __init__(self, app, otp_svc):
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.OTPService = otp_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/account/totp", self.prepare_totp_if_not_active)
		web_app.router.add_put("/account/totp", self.activate_totp)
		web_app.router.add_delete("/account/totp", self.deactivate_totp)
		web_app.router.add_get("/admin/credentials/{credentials_id}/authn/totp", self.admin_get_totp_status)
		web_app.router.add_delete("/admin/credentials/{credentials_id}/authn/totp", self.admin_deactivate_totp)

		# DEPRECATED
		# >>>
		web_app.router.add_put("/account/set-totp", self.activate_totp)
		web_app.router.add_put("/account/unset-totp", self.deactivate_totp)
		# <<<


	@asab.web.tenant.allow_no_tenant
	async def prepare_totp_if_not_active(self, request):
		"""
		Return the status of TOTP setting

		If not activated, generate and return a new TOTP secret.
		"""
		authz = asab.contextvars.Authz.get()
		if await self.OTPService.has_activated_totp(authz.CredentialsId):
			response: dict = {
				"result": "OK",
				"active": True
			}
		else:
			response: dict = await self.OTPService.prepare_totp(authz.Session, authz.CredentialsId)
			response.update({
				"result": "OK",
				"active": False
			})

		return asab.web.rest.json_response(request, response)

	@asab.web.rest.json_schema_handler(schema.ACTIVATE_OTP)
	@asab.web.tenant.allow_no_tenant
	async def activate_totp(self, request, *, json_data):
		"""
		Activate TOTP for the current user

		This requires that a TOTP secret is already prepared for the user.
		"""
		authz = asab.contextvars.Authz.get()
		otp = json_data.get("otp")
		try:
			await self.OTPService.activate_prepared_totp(authz.Session, authz.CredentialsId, otp)
		except exceptions.TOTPActivationError:
			return asab.web.rest.json_response(request, {"result": "FAILED"}, status=400)
		return asab.web.rest.json_response(request, {"result": "OK"})


	@asab.web.tenant.allow_no_tenant
	async def deactivate_totp(self, request):
		"""
		Deactivate TOTP for the current user

		The user's TOTP secret is deleted.
		"""
		authz = asab.contextvars.Authz.get()
		try:
			await self.OTPService.deactivate_totp(authz.CredentialsId)
		except exceptions.TOTPDeactivationError:
			return asab.web.rest.json_response(request, {"result": "FAILED"}, status=400)

		return asab.web.rest.json_response(request, {"result": "OK"})


	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
	async def admin_get_totp_status(self, request):
		"""
		See if target credentials have TOTP activated
		"""
		credentials_id = request.match_info["credentials_id"]
		if await self.OTPService.has_activated_totp(credentials_id):
			return asab.web.rest.json_response(request, {"active": True})
		else:
			return asab.web.rest.json_response(request, {"active": False})


	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
	async def admin_deactivate_totp(self, request):
		"""
		Deactivate TOTP for target credentials
		"""
		credentials_id = request.match_info["credentials_id"]
		try:
			await self.OTPService.deactivate_totp(credentials_id)
		except exceptions.TOTPDeactivationError:
			return asab.web.rest.json_response(request, {"result": "FAILED"}, status=400)

		return asab.web.rest.json_response(request, {"result": "OK"})
