import hashlib
import logging
import datetime

import asab
import bson

from ... import exceptions
from ...generic import generate_ergonomic_token
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
		self.StorageService = app.get_service("asab.StorageService")

		self.AuthWebUIBaseUrl = app.AuthWebUiUrl.rstrip("/")
		self.Expiration = asab.Config.getseconds("seacatauth:password", "password_reset_expiration")

		self.ResetPwdPath = "/#/reset-password"

		app.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)

	async def _on_housekeeping(self, event_name):
		await self._delete_expired_password_reset_tokens()

	async def _delete_expired_password_reset_tokens(self):
		collection = self.StorageService.Database[self.ChangePasswordCollection]
		query_filter = {"exp": {"$lt": datetime.datetime.now(datetime.timezone.utc)}}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.log(asab.LOG_NOTICE, "Expired password reset tokens deleted", struct_data={
				"count": result.deleted_count
			})


	async def delete_password_reset_tokens_by_cid(self, credentials_id: str):
		collection = self.StorageService.Database[self.ChangePasswordCollection]
		query_filter = {"cid": credentials_id}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.log(asab.LOG_NOTICE, "Password reset tokens deleted", struct_data={
				"cid": credentials_id,
				"count": result.deleted_count
			})


	async def create_password_reset_token(self, credentials_id: str, expiration: int | None = None):
		"""
		Create a password reset object
		"""
		password_reset_token = generate_ergonomic_token(length=20)
		token_id = await self._token_id_from_token_string(password_reset_token)
		upsertor = self.StorageService.upsertor(self.ChangePasswordCollection, obj_id=token_id)
		upsertor.set("cid", credentials_id)
		upsertor.set("exp", datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
			seconds=expiration if expiration is not None else self.Expiration))

		await upsertor.execute(event_type=EventTypes.PWD_RESET_TOKEN_CREATED)
		L.log(asab.LOG_NOTICE, "Password reset token created", struct_data={"cid": credentials_id})
		return password_reset_token


	async def delete_password_reset_token(self, password_reset_token: str):
		token_id = await self._token_id_from_token_string(password_reset_token)
		await self.StorageService.delete(self.ChangePasswordCollection, token_id)
		L.log(asab.LOG_NOTICE, "Password reset token deleted", struct_data={"pwd_token": password_reset_token})


	async def get_password_reset_token_details(self, password_reset_token: str):
		token_id = await self._token_id_from_token_string(password_reset_token)
		token = await self.StorageService.get(self.ChangePasswordCollection, token_id)
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

		pwdreset_token = await self.create_password_reset_token(credentials_id=credentials_id, expiration=expiration)

		# Send the message
		email = creds.get("email")
		username = creds.get("username")
		phone = creds.get("phone")
		reset_url = "{}{}?pwd_token={}".format(self.AuthWebUIBaseUrl, self.ResetPwdPath, pwdreset_token)
		successful = await self.CommunicationService.password_reset(
			email=email, username=username, phone=phone, reset_url=reset_url, welcome=is_new_user
		)

		if successful:
			L.log(asab.LOG_NOTICE, "Password change initiated", struct_data={"cid": credentials_id})
			return True
		else:
			await self.delete_password_reset_token(pwdreset_token)
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


	async def _token_id_from_token_string(self, password_reset_token):
		return hashlib.sha256(password_reset_token.encode("ascii")).digest()
