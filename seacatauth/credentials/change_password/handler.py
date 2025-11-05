import logging
import asyncio

import asab
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.contextvars

from ... import exceptions, generic, AuditLogger
from ...models.const import ResourceId
from ...last_activity import EventCode
from .. import schema


L = logging.getLogger(__name__)


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


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.noauth
	async def password_policy(self, request):
		"""
		Get minimum password requirements
		"""
		response_data = await self.ChangePasswordService.password_policy()
		return asab.web.rest.json_response(request, response_data)


	@asab.web.rest.json_schema_handler(schema.CHANGE_PASSWORD)
	@asab.web.tenant.allow_no_tenant
	async def change_password(self, request, *, json_data):
		"""
		Set a new password (with current password authentication)
		"""
		authz = asab.contextvars.Authz.get()
		new_password = json_data.get("newpassword")
		old_password = json_data.get("oldpassword")
		credentials_id = authz.CredentialsId
		from_ip = generic.get_request_access_ips(request)

		# Authenticate with the old password
		authenticated = await self.CredentialsService.authenticate(
			credentials_id, {"password": old_password})
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

	@asab.web.rest.json_schema_handler(schema.RESET_PASSWORD)
	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.noauth
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


	@asab.web.rest.json_schema_handler(schema.REQUEST_PASSWORD_RESET_ADMIN)
	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require(ResourceId.CREDENTIALS_EDIT)
	async def admin_request_password_reset(self, request, *, json_data):
		"""
		Send a password reset link to specified user and return it in the response if the caller is superuser.
		As long as either email communication is successful or the caller is superuser, the result is
		considered successful.
		"""
		response_data = {}
		authz = asab.contextvars.Authz.get()
		credentials_id = json_data.get("credentials_id")
		try:
			credentials = await self.CredentialsService.get(credentials_id)
		except exceptions.CredentialsNotFoundError:
			L.error("Password reset denied: Credentials not found.", struct_data={"cid": credentials_id})
			return asab.web.rest.json_response(request, status=404, data={
				"result": "ERROR",
				"tech_err": "Credentials {!r} not found.".format(credentials_id),
				"error": "SeaCatAuthError|Credentials not found",
			})

		# Deny password reset to suspended credentials
		if credentials.get("suspended") is True:
			L.error("Password reset denied: Credentials suspended.", struct_data={"cid": credentials_id})
			return asab.web.rest.json_response(request, status=400, data={
				"result": "ERROR",
				"tech_err": "Credentials {!r} are suspended.".format(credentials_id),
				"error": "SeaCatAuthError|Credentials are suspended",
			})

		# Check if password reset link can be disclosed (in email or at least in the response)
		password_reset_url = None
		url_disclosed = False
		can_get_link_in_response = authz.has_superuser_access()
		email_service_enabled = await self.ChangePasswordService.CommunicationService.is_channel_enabled("email")
		can_email_to_target = await self.ChangePasswordService.CommunicationService.can_send_to_target(
			credentials, "email")

		# Superusers receive the password reset link in response
		if can_get_link_in_response:
			password_reset_url = await self.ChangePasswordService.init_password_reset(
				credentials,
				expiration=json_data.get("expiration"),
			)
			response_data["password_reset_url"] = password_reset_url
			url_disclosed = True

		# Check email communication availability and send email
		if not email_service_enabled:
			L.error("Password reset denied: Email service not available.", struct_data={
				"cid": credentials_id})
			email_delivery_result = {
				"result": "ERROR",
				"tech_err": "Email service not available.",
				"error": "SeaCatAuthError|Email service not available",
			}
		elif not can_email_to_target:
			L.error("Password reset denied: Credentials have no email address.", struct_data={
				"cid": credentials_id})
			email_delivery_result = {
				"result": "ERROR",
				"tech_err": "Credentials have no email address.",
				"error": "SeaCatAuthError|Credentials have no email address",
			}
		else:
			if not password_reset_url:
				password_reset_url = await self.ChangePasswordService.init_password_reset(
					credentials,
					expiration=json_data.get("expiration"),
				)
			# Email the link to the user
			try:
				await self.ChangePasswordService.CommunicationService.password_reset(
					credentials=credentials,
					reset_url=password_reset_url,
					new_user=False
				)
				url_disclosed = True
				email_delivery_result = {"result": "OK"}
			except exceptions.ServerCommunicationError:
				email_delivery_result = {
					"result": "ERROR",
					"tech_err": "Cannot connect to the email service.",
					"error": "SeaCatAuthError|Cannot connect to the email service",
				}
			except exceptions.MessageDeliveryError:
				email_delivery_result = {
					"result": "ERROR",
					"tech_err": "Failed to send password reset link.",
					"error": "SeaCatAuthError|Failed to send password reset link",
				}

		response_data["email_sent"] = email_delivery_result
		if url_disclosed:
			response_data["result"] = "OK"
			status = 200
		else:
			response_data.update(email_delivery_result)
			status = 400
		return asab.web.rest.json_response(request, response_data, status=status)


	@asab.web.rest.json_schema_handler(schema.REQUEST_LOST_PASSWORD_RESET)
	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.noauth
	async def lost_password(self, request, *, json_data):
		"""
		Request a password reset link

		NOTE: This must always return a positive response as a measure to avoid
		sensitive information disclosure on public API.
		"""
		await asyncio.sleep(5)  # Safety time cooldown
		access_ips = generic.get_request_access_ips(request)
		ident = json_data["ident"]
		credentials_id = await self.CredentialsService.locate(ident, stop_at_first=True)
		if credentials_id is None:
			L.log(asab.LOG_NOTICE, "Lost password reset denied: Ident matched no credentials", struct_data={
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

		# Deny password reset to suspended credentials
		if credentials.get("suspended") is True:
			L.error("Lost password reset denied: Credentials suspended.", struct_data={
				"cid": credentials_id, "from": access_ips})
			return asab.web.rest.json_response(request, status=400, data={
				"result": "ERROR",
				"tech_err": "Credentials suspended.",
			})

		# Check if password reset link can be sent
		if not await self.ChangePasswordService.CommunicationService.can_send_to_target(credentials, "email"):
			L.log(asab.LOG_NOTICE, "Lost password reset failed: No way to communicate password reset link.", struct_data={
				"cid": credentials_id, "from": access_ips})
			# Avoid information disclosure
			return asab.web.rest.json_response(request, {"result": "OK"})

		# Create the password reset link
		password_reset_url = await self.ChangePasswordService.init_password_reset(credentials)

		# Email the link to the user
		try:
			await self.ChangePasswordService.CommunicationService.password_reset(
				credentials=credentials,
				reset_url=password_reset_url,
				new_user=False
			)
		except exceptions.ServerCommunicationError:
			L.error("Lost password reset failed: Failed to connect to email service.", struct_data={
				"cid": credentials_id, "from": access_ips})
		except exceptions.MessageDeliveryError:
			L.error("Lost password reset failed: Failed to send password reset link.", struct_data={
				"cid": credentials_id, "from": access_ips})

		# Avoid information disclosure
		return asab.web.rest.json_response(request, {"result": "OK"})
