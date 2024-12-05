import logging
import asyncio

import asab
import asab.web.rest
import asab.web.webcrypto

from ... import exceptions, generic, AuditLogger
from ...last_activity import EventCode
from ...decorators import access_control

#

L = logging.getLogger(__name__)

#


class ChangePasswordHandler(object):
	"""
	Manage password

	---
	tags: ["Passwords"]
	"""

	def __init__(self, app, change_password_svc):
		self.ChangePasswordService = change_password_svc
		self.LastActivityService = app.get_service("seacatauth.LastActivityService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_put("/password", self.admin_request_password_reset)
		web_app.router.add_get("/account/password/policy", self.password_policy)
		web_app.router.add_put("/account/password-change", self.change_password)
		web_app.router.add_get("/public/password/policy", self.password_policy)
		web_app.router.add_put("/public/password-reset", self.reset_password)
		web_app.router.add_put("/public/lost-password", self.lost_password)

		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get("/public/password/policy", self.password_policy)
		web_app_public.router.add_put("/public/password-reset", self.reset_password)
		web_app_public.router.add_put("/public/lost-password", self.lost_password)

		# Back-compat; To be removed in next major version
		# >>>
		web_app.router.add_put("/public/password-change", self.change_password)
		web_app_public.router.add_put("/public/password-change", self.change_password)
		# <<<


	async def password_policy(self, request):
		"""
		Get minimum password requirements
		"""
		response_data = await self.ChangePasswordService.password_policy()
		return asab.web.rest.json_response(request, response_data)


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
		new_password = json_data.get("newpassword")
		old_password = json_data.get("oldpassword")
		credentials_id = request.Session.Credentials.Id
		from_ip = generic.get_request_access_ips(request)

		# Authenticate with the old password
		authenticated = await self.CredentialsService.authenticate(
			request.Session.Credentials.Id, {"password": old_password})
		if not authenticated:
			AuditLogger.log(asab.LOG_NOTICE, "Password change failed: Authentication failed", struct_data={
				"cid": credentials_id, "from_ip": from_ip})
			await self.LastActivityService.update_last_activity(
				EventCode.PASSWORD_CHANGE_FAILED, credentials_id=credentials_id, from_ip=from_ip)
			return asab.web.rest.json_response(request, status=401, data={
				"result": "UNAUTHORIZED",
				"tech_message": "Authentication failed.",
			})

		# Verify that the new password is different from the old one
		# TODO: Users should not reuse their last 10 passwords at least
		if new_password == old_password:
			AuditLogger.log(asab.LOG_NOTICE, "Password change denied: Reusing old passwords is not allowed.", struct_data={
				"cid": credentials_id, "from_ip": from_ip})
			await self.LastActivityService.update_last_activity(
				EventCode.PASSWORD_CHANGE_FAILED, credentials_id=credentials_id, from_ip=from_ip)
			return asab.web.rest.json_response(request, status=400, data={
				"result": "FAILED",
				"tech_message": "Reusing old passwords is not allowed.",
			})

		# Change the password
		try:
			await self.ChangePasswordService.change_password(credentials_id, new_password)
		except exceptions.WeakPasswordError as e:
			AuditLogger.log(asab.LOG_NOTICE, "Password change denied: New password too weak.", struct_data={
				"cid": credentials_id, "from_ip": from_ip})
			await self.LastActivityService.update_last_activity(
				EventCode.PASSWORD_CHANGE_FAILED, credentials_id=credentials_id, from_ip=from_ip)
			return asab.web.rest.json_response(request, status=400, data={
				"result": "FAILED",
				"tech_message": str(e),
			})
		except Exception as e:
			L.exception("Password change failed: {}".format(e))
			AuditLogger.log(asab.LOG_NOTICE, "Password change failed: {}".format(e.__class__.__name__), struct_data={
				"cid": credentials_id, "from_ip": from_ip})
			await self.LastActivityService.update_last_activity(
				EventCode.PASSWORD_CHANGE_FAILED, credentials_id=credentials_id, from_ip=from_ip)
			return asab.web.rest.json_response(request, status=401, data={"result": "FAILED"})

		# Record the change in audit
		AuditLogger.log(
			asab.LOG_NOTICE, "Password change successful",
			struct_data={"cid": credentials_id, "from_ip": from_ip}
		)
		await self.LastActivityService.update_last_activity(
			EventCode.PASSWORD_CHANGE_SUCCESS, credentials_id=credentials_id, from_ip=from_ip)

		return asab.web.rest.json_response(request, {"result": "OK"})

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
		# Safety timeout
		await asyncio.sleep(5)

		password_reset_token = json_data.get("pwd_token")
		new_password = json_data.get("newpassword")
		from_ip = generic.get_request_access_ips(request)

		# "Authenticate" using the password reset token
		try:
			password_reset_details = await self.ChangePasswordService.get_password_reset_token_details(
				password_reset_token)
			credentials_id = password_reset_details["cid"]
		except KeyError:
			AuditLogger.log(
				asab.LOG_NOTICE, "Password reset failed: Invalid password reset token",
				struct_data={"from_ip": from_ip, "token": password_reset_token}
			)
			return asab.web.rest.json_response(request, status=401, data={"result": "FAILED"})

		# Change the password
		try:
			await self.ChangePasswordService.change_password(credentials_id, new_password)
		except exceptions.CredentialsSuspendedError:
			AuditLogger.log(asab.LOG_NOTICE, "Password reset denied: Credentials suspended", struct_data={
				"cid": credentials_id})
			await self.LastActivityService.update_last_activity(
				EventCode.PASSWORD_CHANGE_FAILED, credentials_id=credentials_id, from_ip=from_ip)
			return asab.web.rest.json_response(request, status=401, data={"result": "FAILED"})
		except exceptions.WeakPasswordError as e:
			AuditLogger.log(asab.LOG_NOTICE, "Password reset denied: New password too weak.", struct_data={
				"cid": credentials_id, "from_ip": from_ip})
			await self.LastActivityService.update_last_activity(
				EventCode.PASSWORD_CHANGE_FAILED, credentials_id=credentials_id, from_ip=from_ip)
			return asab.web.rest.json_response(request, status=400, data={
				"result": "FAILED",
				"tech_message": str(e),
			})
		except Exception as e:
			L.exception("Password reset failed: {}".format(e))
			AuditLogger.log(asab.LOG_NOTICE, "Password reset failed: {}".format(e.__class__.__name__), struct_data={
				"cid": credentials_id, "from_ip": from_ip})
			await self.LastActivityService.update_last_activity(
				EventCode.PASSWORD_CHANGE_FAILED, credentials_id=credentials_id, from_ip=from_ip)
			return asab.web.rest.json_response(request, status=401, data={"result": "FAILED"})

		# Delete all the credentials' tokens after a successful password change
		await self.ChangePasswordService.delete_password_reset_tokens_by_cid(credentials_id)

		# Record in audit
		AuditLogger.log(
			asab.LOG_NOTICE, "Password reset successful",
			struct_data={"cid": credentials_id, "from_ip": from_ip}
		)
		await self.LastActivityService.update_last_activity(
			EventCode.PASSWORD_CHANGE_SUCCESS, credentials_id=credentials_id, from_ip=from_ip)

		return asab.web.rest.json_response(request, {"result": "OK"})


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["credentials_id"],
		"properties": {
			"credentials_id": {"type": "string"},
			"expiration": {"type": "number"},
		}
	})
	@access_control("seacat:credentials:edit")
	async def admin_request_password_reset(self, request, *, json_data):
		"""
		Send a password reset link to specified user
		"""
		credentials_id = json_data.get("credentials_id")
		try:
			credentials = await self.CredentialsService.get(credentials_id)
		except exceptions.CredentialsNotFoundError:
			L.log(asab.LOG_NOTICE, "Password reset denied: Credentials not found.", struct_data={
				"cid": credentials_id})
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)

		try:
			reset_url = await self.ChangePasswordService.init_password_reset_by_admin(
				credentials,
				expiration=json_data.get("expiration")
			)
		except exceptions.CredentialsNotFoundError:
			L.log(asab.LOG_NOTICE, "Password reset denied: Credentials not found", struct_data={
				"cid": credentials_id})
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)
		except exceptions.CredentialsSuspendedError:
			L.log(asab.LOG_NOTICE, "Password reset denied: Credentials suspended", struct_data={
				"cid": credentials_id})
			return asab.web.rest.json_response(request, {"result": "NOT-FOUND"}, status=404)
		except exceptions.MessageDeliveryError as e:
			L.error("Failed to send password change link: {}".format(e), struct_data={"cid": credentials_id})
			return asab.web.rest.json_response(request, {
				"result": "ERROR",
				"tech_err": "Failed to send email with password reset link.",
				"error": "PasswordResetError|Failed to send email with password reset link.",
			}, status=500)

		response_data = {"result": "OK"}
		if reset_url:
			# Password reset URL was not sent because CommunicationService is disabled
			# Add the URL to admin response
			response_data["reset_url"] = reset_url

		return asab.web.rest.json_response(request, response_data)


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
			L.log(asab.LOG_NOTICE, "Ident matched no credentials", struct_data={
				"ident": ident, "from": access_ips})
			# Avoid information disclosure
			return asab.web.rest.json_response(request, {"result": "OK"})

		try:
			credentials = await self.CredentialsService.get(credentials_id)
		except exceptions.CredentialsNotFoundError:
			L.error("Lost password reset denied: Credentials not found", struct_data={
				"cid": credentials_id, "from": access_ips})
			# Avoid information disclosure
			return asab.web.rest.json_response(request, {"result": "OK"})

		try:
			await self.ChangePasswordService.init_lost_password_reset(credentials)
		except exceptions.CredentialsSuspendedError:
			L.error("Lost password reset denied: Credentials suspended", struct_data={
				"cid": credentials_id, "from": access_ips})
			# Avoid information disclosure
			return asab.web.rest.json_response(request, {"result": "OK"})
		except exceptions.MessageDeliveryError as e:
			L.error("Lost password reset failed: Failed to send password change link ({})".format(e), struct_data={
				"cid": credentials_id, "from": access_ips})
			# Avoid information disclosure
			return asab.web.rest.json_response(request, {"result": "OK"})

		return asab.web.rest.json_response(request, {"result": "OK"})
