import logging
import asyncio

import asab
import asab.web.rest
import asab.web.webcrypto

from ...decorators import access_control

#

L = logging.getLogger(__name__)

#


class ChangePasswordHandler(object):


	def __init__(self, app, change_password_svc):
		self.ChangePasswordService = change_password_svc

		self.SessionService = app.get_service("seacatauth.SessionService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.AuditService = app.get_service("seacatauth.AuditService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_put("/password", self.init_password_change)
		web_app.router.add_put("/public/password-change", self.change_password)
		web_app.router.add_put("/public/password-reset", self.reset_password)
		web_app.router.add_put("/public/lost-password", self.lost_password)

		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_put("/password", self.init_password_change)
		web_app_public.router.add_put("/public/password-change", self.change_password)
		web_app_public.router.add_put("/public/password-reset", self.reset_password)
		web_app_public.router.add_put("/public/lost-password", self.lost_password)


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": [
			"oldpassword",
			"newpassword",
		],
		"properties": {
			"oldpassword": {"type": "string"},
			"newpassword": {"type": "string"},
		}
	})
	@access_control()
	async def change_password(self, request, *, json_data):
		"""
		Verify old password and change it to new password
		"""
		result = await self.ChangePasswordService.change_password(
			request.Session,
			json_data.get("oldpassword"),
			json_data.get("newpassword"),
		)

		return asab.web.rest.json_response(request, {"result": result})

	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": [
			"newpassword",
			"pwd_token"  # Password reset token
		],
		"properties": {
			"newpassword": {
				"type": "string"
			},
			"pwd_token": {
				"type": "string",
				"description": "One-time code for password reset"
			},
		}
	})
	async def reset_password(self, request, *, json_data):
		"""
		Set a new password using pwd_token obtained in "Lost password" procedure
		"""
		# TODO: this call needs to be encrypted
		result = await self.ChangePasswordService.change_password_by_pwdreset_id(
			json_data.get("pwd_token"),
			json_data.get("newpassword"),
		)

		return asab.web.rest.json_response(request, {"result": result})

	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["credentials_id"],
		"properties": {
			"credentials_id": {"type": "string"},
			"expiration": {"type": "number"},
		}
	})
	@access_control("authz:tenant:admin")
	async def init_password_change(self, request, *, json_data):
		"""
		Directly creates a password reset request. This should be called by admin only.
		For user-initiated password reset use `lost_password` method.
		"""
		result = await self.ChangePasswordService.init_password_change(
			json_data.get("credentials_id"),
			expiration=json_data.get("expiration")
		)
		return asab.web.rest.json_response(request, {"result": result})

	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["ident"],
		"properties": {
			"ident": {"type": "string"},
		}
	})
	async def lost_password(self, request, *, json_data):
		await asyncio.sleep(5)  # Safety time cooldown
		ident = json_data["ident"]
		await self.ChangePasswordService.lost_password(ident)
		response = {"result": "OK"}  # Since this is public, do not disclose the true result
		return asab.web.rest.json_response(request, response)
