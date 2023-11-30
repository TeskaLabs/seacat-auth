import logging
import asyncio

import asab
import asab.web.rest
import asab.web.webcrypto

from ... import exceptions, generic
from ...decorators import access_control

#

L = logging.getLogger(__name__)

#


class ChangePasswordHandler(object):
	"""
	Manage password

	---
	tags: ["Manage password"]
	"""

	def __init__(self, app, change_password_svc):
		self.ChangePasswordService = change_password_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_put("/admin/password", self.admin_request_password_change)
		web_app.router.add_put("/account/password-change", self.change_password)
		web_app.router.add_put("/public/password-reset", self.reset_password)
		web_app.router.add_put("/public/lost-password", self.lost_password)

		web_app_public = app.PublicWebContainer.WebApp
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
		Set a new password (with current password authentication)
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
		Set a new password (with password token authentication)
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
	@access_control("seacat:credentials:edit")
	async def admin_request_password_change(self, request, *, json_data):
		"""
		Send a password reset link to specified user
		"""
		credentials_id = json_data.get("credentials_id")
		try:
			await self.ChangePasswordService.init_password_change(
				credentials_id,
				expiration=json_data.get("expiration")
			)
		except exceptions.CommunicationError:
			L.error("Failed to send password change link.", struct_data={"cid": credentials_id})
			return asab.web.rest.json_response(request, {"result": "FAILED"}, status=500)

		return asab.web.rest.json_response(request, {"result": "OK"})

	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["ident"],
		"properties": {
			"ident": {"type": "string"},
		}
	})
	async def lost_password(self, request, *, json_data):
		"""
		Request a password reset link

		NOTE: This must always return a positive response as a measure to avoid
		sensitive information disclosure on public API.
		"""
		await asyncio.sleep(5)  # Safety time cooldown
		access_ips = generic.get_request_access_ips(request)
		ident = json_data["ident"]
		credentials_id = await self.ChangePasswordService.CredentialsService.locate(ident, stop_at_first=True)
		if credentials_id is None:
			L.log(asab.LOG_NOTICE, "Ident matched no credentials.", struct_data={
				"ident": ident, "from": access_ips})
			# Avoid information disclosure
			return asab.web.rest.json_response(request, {"result": "OK"})

		try:
			await self.ChangePasswordService.init_password_change(credentials_id)
		except exceptions.CommunicationError:
			L.error("Failed to send password change link.", struct_data={
				"cid": credentials_id, "from": access_ips})
			# Avoid information disclosure
			return asab.web.rest.json_response(request, {"result": "OK"})

		return asab.web.rest.json_response(request, {"result": "OK"})
