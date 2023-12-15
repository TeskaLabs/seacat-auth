import asyncio
import logging
import datetime

import asab

from ... import exceptions
from ...generic import generate_ergonomic_token
from ...audit import AuditCode

from ...events import EventTypes

#

L = logging.getLogger(__name__)

#


class InvalidPasswordResetTokenError(ValueError):
	pass


class ChangePasswordService(asab.Service):

	ChangePasswordCollection = "p"

	def __init__(self, app, cred_service, service_name="seacatauth.ChangePasswordService"):
		super().__init__(app, service_name)

		self.CredentialsService = cred_service
		self.CommunicationService = app.get_service("seacatauth.CommunicationService")
		self.AuditService = app.get_service("seacatauth.AuditService")
		self.StorageService = app.get_service("asab.StorageService")

		self.AuthWebUIBaseUrl = app.AuthWebUiUrl.rstrip("/")
		self.Expiration = asab.Config.getseconds("seacatauth:password", "password_reset_expiration")

		self.ResetPwdPath = "/#/reset-password"

		app.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)

	async def _on_housekeeping(self, event_name):
		await self._delete_expired_pwdreset_tokens()

	async def _delete_expired_pwdreset_tokens(self):
		collection = self.StorageService.Database[self.ChangePasswordCollection]
		query_filter = {"exp": {"$lt": datetime.datetime.now(datetime.timezone.utc)}}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.log(asab.LOG_NOTICE, "Expired password reset tokens deleted.", struct_data={
				"count": result.deleted_count
			})

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
		request_id = await upsertor.execute(event_type=EventTypes.PWD_RESET_TOKEN_CREATED)
		assert pwd_change_id == request_id
		L.log(asab.LOG_NOTICE, "Password reset token created", struct_data={"pwd_token": request_id})
		return request_id


	async def delete_pwdreset_token(self, pwdreset_id: str):
		await self.StorageService.delete(self.ChangePasswordCollection, pwdreset_id)
		L.log(asab.LOG_NOTICE, "Password reset token deleted", struct_data={"pwd_token": pwdreset_id})


	async def get_password_reset_token_credentials_id(self, password_reset_token: str):
		token = await self.StorageService.get(self.ChangePasswordCollection, password_reset_token)
		if token["exp"] < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("Password reset token expired.")
		return token


	async def init_password_change(self, credentials_id: str, is_new_user: bool = False, expiration: float = None):
		'''
		Parameter `new` states, if the user has been just created, so maybe a different email will be sent to him/her
		Parameter `expires_in` is in seconds.
		'''

		# Verify if credentials exists
		creds = await self.CredentialsService.get(credentials_id)
		if creds is None:
			L.error("Cannot find credentials", struct_data={"cid": credentials_id})
			return False

		if expiration is None:
			expiration = self.Expiration
		pwd_change_id = generate_ergonomic_token(length=20)
		pwd_change_builders = [{
			"cid": credentials_id,
			"exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=expiration)
		}]

		await self.create_pwdreset_token(pwd_change_id, pwd_change_builders)

		# Send the message
		email = creds.get("email")
		username = creds.get("username")
		phone = creds.get("phone")
		reset_url = "{}{}?pwd_token={}".format(self.AuthWebUIBaseUrl, self.ResetPwdPath, pwd_change_id)
		successful = await self.CommunicationService.password_reset(
			email=email, username=username, phone=phone, reset_url=reset_url, welcome=is_new_user
		)

		if successful:
			L.log(asab.LOG_NOTICE, "Password change initiated", struct_data={"cid": credentials_id})
			return True
		else:
			await self.delete_pwdreset_token(pwd_change_id)
			raise exceptions.CommunicationError(
				"Failed to send password reset link.", credentials_id=credentials_id)


	async def change_password(self, credentials_id: str, new_password: str):
		provider = self.CredentialsService.get_provider(credentials_id)

		# Remove "password" from enforced factors
		credentials = await self.CredentialsService.get(credentials_id)
		enforce_factors = set(credentials.get("enforce_factors", []))
		if "password" in enforce_factors:
			enforce_factors.remove("password")

		# Update password in DB
		await provider.update(credentials_id, {
			"password": new_password,
			"enforce_factors": list(enforce_factors)
		})
