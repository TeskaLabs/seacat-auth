import asyncio
import logging
import datetime

import asab

from ...generic import generate_ergonomic_token
from ...audit import AuditCode

#

L = logging.getLogger(__name__)

#


class ChangePasswordService(asab.Service):

	ChangePasswordCollection = "p"

	def __init__(self, app, cred_service, service_name="seacatauth.ChangePasswordService"):
		super().__init__(app, service_name)

		self.CredentialsService = cred_service
		self.CommunicationService = app.get_service("seacatauth.CommunicationService")
		self.AuditService = app.get_service("seacatauth.AuditService")
		self.StorageService = app.get_service("asab.StorageService")

		self.AuthWebUIBaseUrl = asab.Config.get("general", "auth_webui_base_url").rstrip("/")
		self.Expiration = asab.Config.getseconds("seacatauth:password", "password_reset_expiration")

		self.ResetPwdPath = "/#/reset-password"

		app.PubSub.subscribe("Application.tick/3600!", self._on_tick)

	async def _on_tick(self, event_name):
		await self.delete_expired_pwdreset_tokens()

	async def delete_expired_pwdreset_tokens(self):
		expired = []
		requests = await self.list_pwdreset_tokens()
		for r in requests["data"]:
			if datetime.datetime.now(datetime.timezone.utc) > r["exp"]:
				expired.append(r["_id"])
		for pwd_id in expired:
			await self.delete_pwdreset_token(pwdreset_id=pwd_id)

	async def delete_pwdreset_tokens_by_cid(self, cid):
		expired = []
		requests = await self.list_pwdreset_tokens()
		for r in requests["data"]:
			if r["cid"] == cid:
				expired.append(r["_id"])
		for pwd_id in expired:
			await self.delete_pwdreset_token(pwdreset_id=pwd_id)

	async def list_pwdreset_tokens(self, page: int = 0, limit: int = None):
		collection = self.StorageService.Database[self.ChangePasswordCollection]

		query_filter = {}
		cursor = collection.find(query_filter)

		cursor.sort('_c', -1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		requests = []
		async for request_dict in cursor:
			requests.append(request_dict)

		return {
			'data': requests,
			'count': await collection.count_documents(query_filter)
		}

	async def create_pwdreset_token(self, pwd_change_id: str, request_builders: list):
		upsertor = self.StorageService.upsertor(self.ChangePasswordCollection, obj_id=pwd_change_id)
		for request_builder in request_builders:
			for key, value in request_builder.items():
				upsertor.set(key, value)
		request_id = await upsertor.execute()
		assert pwd_change_id == request_id
		L.log(asab.LOG_NOTICE, "Password reset token created", struct_data={"pwd_token": request_id})
		return request_id

	async def delete_pwdreset_token(self, pwdreset_id: str):
		await self.StorageService.delete(self.ChangePasswordCollection, pwdreset_id)
		L.log(asab.LOG_NOTICE, "Password reset token deleted", struct_data={"pwd_token": pwdreset_id})

	async def get_pwdreset_token(self, pwdreset_id: str):
		return await self.StorageService.get(self.ChangePasswordCollection, pwdreset_id)

	async def init_password_change(self, credentials_id: str, is_new_user: bool = False, expiration: float = None):
		'''
		Parameter `new` states, if the user has been just created, so maybe a different email will be sent to him/her
		Parameter `expires_in` is in seconds.
		'''

		# Verify if credentials exists
		creds = await self.CredentialsService.get(credentials_id)
		if creds is None:
			L.warning("Cannot find credentials", struct_data={"cid": credentials_id})
			return False

		if expiration is None:
			expiration = self.Expiration
		pwd_change_id = generate_ergonomic_token(length=20)
		pwd_change_builders = [{
			"cid": credentials_id,
			"exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=expiration)
		}]

		await self.create_pwdreset_token(pwd_change_id, pwd_change_builders)

		# Sent the message
		email = creds.get("email")
		username = creds.get("username")
		phone = creds.get("phone")
		reset_url = "{}{}?pwd_token={}".format(self.AuthWebUIBaseUrl, self.ResetPwdPath, pwd_change_id)
		await self.CommunicationService.password_reset(
			email=email, username=username, phone=phone, reset_url=reset_url, welcome=is_new_user
		)

		L.log(asab.LOG_NOTICE, "Password change initiated", struct_data={'cid': credentials_id})

		return True

	async def _do_change_password(self, credentials_id, new_password: str):
		try:
			provider = self.CredentialsService.get_provider(credentials_id)
		except KeyError:
			L.warning("Provider not found", struct_data={'cid': credentials_id})
			return "FAILED"

		assert(provider is not None)

		# Remove "password" from enforced factors
		credentials = await self.CredentialsService.get(credentials_id)
		enforce_factors = set(credentials.get("enforce_factors", []))
		if "password" in enforce_factors:
			enforce_factors.remove("password")

		# Update password in DB
		try:
			await provider.update(credentials_id, {
				"password": new_password,
				"enforce_factors": list(enforce_factors)
			})
		except Exception as e:
			L.exception("Password change failed: {}".format(e), struct_data={'cid': credentials_id})
			return "FAILED"

		L.log(asab.LOG_NOTICE, "Password changed", struct_data={'cid': credentials_id})

		# Record the change in audit
		await self.AuditService.append(
			AuditCode.PASSWORD_CHANGE_SUCCESS,
			{
				'cid': credentials_id
			}
		)

		return "OK"

	async def change_password_by_pwdreset_id(self, pwdreset_id: str, new_password: str):
		await asyncio.sleep(5)  # Safety timeout

		if pwdreset_id is None:
			L.error("No pwdreset_id provided")
			raise ValueError("No pwdreset_id provided")

		# Get password change object from the storage and extract credentials_id from it
		try:
			pwdreset_dict = await self.get_pwdreset_token(pwdreset_id)
		except KeyError:
			L.warning("Password reset request not found", struct_data={'id': pwdreset_id})
			return "INVALID-CODE"
		credentials_id = pwdreset_dict.get('cid')

		# Set new password
		result = await self._do_change_password(credentials_id, new_password)

		#
		if result != "OK":
			await self.AuditService.append(
				AuditCode.PASSWORD_CHANGE_FAILED,
				{
					"cid": credentials_id
				}
			)

		# Delete ALL pwdreset requests with this credentials id
		try:
			await self.delete_pwdreset_tokens_by_cid(cid=credentials_id)
		except Exception as e:
			L.warning(
				"Unable to remove old password change requests: {} ({})".format(type(e), e),
				struct_data={'cid': credentials_id}
			)

		return result

	async def change_password(self, session, old_password: str, new_password: str):
		# TODO: authenticate() could be problematic here, we may introduce another call for this specific purpose
		valid = await self.CredentialsService.authenticate(session.Credentials.Id, {"password": old_password})
		if not valid:
			L.log(
				asab.LOG_NOTICE,
				"Password change failed, old password doesn't match.",
				struct_data={"cid": session.Credentials.Id}
			)
			result = "UNAUTHORIZED"
		else:
			result = await self._do_change_password(session.Credentials.Id, new_password)

		if result != "OK":
			await self.AuditService.append(
				AuditCode.PASSWORD_CHANGE_FAILED,
				{
					"cid": session.Credentials.Id
				}
			)
		return result

	async def lost_password(self, ident):
		credentials_id = await self.CredentialsService.locate(ident, stop_at_first=True)
		if credentials_id is not None:
			await self.init_password_change(credentials_id)
		else:
			L.warning("No credentials matching '{}'".format(ident))
		return True  # Since this is public, don't disclose the true result
