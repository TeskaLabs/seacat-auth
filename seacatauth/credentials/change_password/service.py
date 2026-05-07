import hashlib
import logging
import datetime
import re
import typing

import asab
import asab.exceptions

from ... import exceptions
from ...generic import generate_ergonomic_token
from ...events import EventTypes
from ...authn.provider import AuthnMethodProviderABC


L = logging.getLogger(__name__)


class InvalidPasswordResetTokenError(ValueError):
	pass


class ChangePasswordService(asab.Service):

	ChangePasswordCollection = "p"

	def __init__(self, app, cred_service, service_name="seacatauth.ChangePasswordService"):
		super().__init__(app, service_name)

		self.PasswordMaxLength = asab.Config.getint("seacatauth:password", "max_length")
		self.PasswordMinLength = asab.Config.getint("seacatauth:password", "min_length")
		self.PasswordMinLowerCount = asab.Config.getint("seacatauth:password", "min_lowercase_count")
		self.PasswordMinUpperCount = asab.Config.getint("seacatauth:password", "min_uppercase_count")
		self.PasswordMinDigitCount = asab.Config.getint("seacatauth:password", "min_digit_count")
		self.PasswordMinSpecialCount = asab.Config.getint("seacatauth:password", "min_special_count")

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


	async def _create_password_reset_token(self, credentials_id: str, expiration: int | None = None):
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


	async def initialize(self, app):
		provider = PasswordAuthnMethodProvider(app, self, self.CredentialsService)
		await provider.initialize(app)


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


	async def create_password_reset_token(self, credentials: dict, expiration: float = None):
		"""
		Create a password reset link and send it to the user via email or other way
		"""
		# Deny password reset to suspended credentials
		if credentials.get("suspended") is True:
			raise exceptions.CredentialsSuspendedError(credentials["_id"])

		return await self._create_password_reset_token(credentials_id=credentials["_id"], expiration=expiration)


	async def password_policy(self) -> dict:
		"""
		Password validation requirements
		"""
		return {
			"min_length": self.PasswordMinLength,
			"min_lowercase_count": self.PasswordMinLowerCount,
			"min_uppercase_count": self.PasswordMinUpperCount,
			"min_digit_count": self.PasswordMinDigitCount,
			"min_special_count": self.PasswordMinSpecialCount,
		}


	async def init_password_reset(
		self,
		credentials: dict,
		expiration: float = None,
	):
		"""
		Create a password reset link and send it to the user via email or other way
		"""
		password_reset_token = await self.create_password_reset_token(credentials, expiration=expiration)
		return self.format_password_reset_url(password_reset_token)


	async def admin_request_password_reset(
		self,
		credentials: dict,
		*,
		requester_is_superuser: bool,
		expiration: float | None = None,
		new_user: bool = False,
	) -> dict:
		"""
		Create a password reset link and try to deliver it.

		The operation is considered successful if either:
		- the reset link is successfully sent via email, or
		- the link is disclosed in the response (superuser or email service disabled).
		"""
		credentials_id = credentials.get("_id")
		credentials_have_email: bool = credentials.get("email") not in (None, "")

		# Determine whether email service is enabled (best-effort)
		email_service_enabled: bool | None = None  # None if status cannot be determined due to error
		try:
			email_service_enabled = await self.CommunicationService.is_channel_enabled("email")
		except exceptions.ServerCommunicationError:
			L.log(asab.LOG_NOTICE, "Cannot check email service availability: Communication error.", struct_data={
				"cid": credentials_id
			})

		can_disclose_link_in_response: bool = requester_is_superuser or (email_service_enabled is False)

		# Determine whether we can send email (best-effort)
		can_send_link: bool = False
		if email_service_enabled is True and credentials_have_email:
			try:
				can_send_link = await self.CommunicationService.can_send_to_target(credentials, "email")
			except exceptions.ServerCommunicationError:
				L.log(asab.LOG_NOTICE, "Cannot check email target deliverability: Communication error.", struct_data={
					"cid": credentials_id
				})
				can_send_link = False

		# If we cannot disclose nor send, fail early without creating the link
		if (not can_disclose_link_in_response) and (not can_send_link):
			return {
				"result": "ERROR",
				"tech_err": "Password reset link cannot be delivered.",
				"error": "SeaCatAuthError|Password reset link cannot be delivered",
				"email_sent": {
					"result": "ERROR",
					"tech_err": "No communication channel available.",
					"error": "SeaCatAuthError|No communication channel available",
				},
			}

		# Create the password reset link (primary action)
		try:
			password_reset_url = await self.init_password_reset(credentials, expiration=expiration)
		except exceptions.CredentialsSuspendedError:
			return {
				"result": "ERROR",
				"tech_err": "Credentials are suspended.",
				"error": "SeaCatAuthError|Credentials are suspended",
				"email_sent": {"result": "SKIPPED"},
			}
		except Exception as e:
			L.exception("Password reset link creation failed: {}".format(e))
			return {
				"result": "ERROR",
				"tech_err": "Password reset link creation failed.",
				"error": "SeaCatAuthError|Password reset link creation failed",
				"email_sent": {"result": "SKIPPED"},
			}

		response: dict = {
			"result": "OK",
			"email_sent": {"result": "SKIPPED"},
		}

		if can_disclose_link_in_response:
			response["password_reset_url"] = password_reset_url

		# Attempt to send email if possible
		if not can_send_link:
			if email_service_enabled is False:
				response["email_sent"] = {
					"result": "ERROR",
					"tech_err": "Email service is not enabled.",
					"error": "SeaCatAuthError|Email service is not enabled",
				}
			elif not credentials_have_email:
				response["email_sent"] = {
					"result": "ERROR",
					"tech_err": "Credentials have no email address.",
					"error": "SeaCatAuthError|Credentials have no email address",
				}
			else:
				response["email_sent"] = {
					"result": "ERROR",
					"tech_err": "Email delivery is not available.",
					"error": "SeaCatAuthError|Email delivery is not available",
				}
		else:
			try:
				await self.CommunicationService.password_reset(
					credentials=credentials,
					reset_url=password_reset_url,
					new_user=new_user,
				)
				response["email_sent"] = {"result": "OK"}
			except exceptions.ServerCommunicationError:
				response["email_sent"] = {
					"result": "ERROR",
					"tech_err": "Email service is temporarily unavailable.",
					"error": "SeaCatAuthError|Email service is temporarily unavailable",
				}
			except exceptions.MessageDeliveryError as e:
				L.error("Cannot send password reset email: {}".format(e), struct_data={
					"cid": credentials_id
				})
				response["email_sent"] = {
					"result": "ERROR",
					"tech_err": "Email delivery error.",
					"error": "SeaCatAuthError|Email delivery error",
				}

		# If link is neither disclosed nor emailed successfully, overall result is failure
		email_ok = response["email_sent"].get("result") == "OK"
		disclosed = "password_reset_url" in response
		if (not disclosed) and (not email_ok):
			response["result"] = "ERROR"

		return response


	def format_password_reset_url(self, password_reset_token):
		reset_url = "{}{}?pwd_token={}".format(self.AuthWebUIBaseUrl, self.ResetPwdPath, password_reset_token)
		return reset_url


	async def change_password(self, credentials_id: str, new_password: str):
		provider = self.CredentialsService.get_provider(credentials_id)

		credentials = await self.CredentialsService.get(credentials_id)

		# Verify that the credentials are not suspended
		if credentials.get("suspended") is True:
			raise exceptions.CredentialsSuspendedError(credentials_id)

		self.verify_password_strength(new_password)

		# Remove "password" from enforced factors
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


	def verify_password_strength(self, password: str):
		if len(password) > self.PasswordMaxLength:
			raise asab.exceptions.ValidationError(
				"Password cannot be longer than {} characters.".format(self.PasswordMaxLength))

		if len(password) < self.PasswordMinLength:
			raise exceptions.WeakPasswordError(
				"Password must be {} or more characters long.".format(self.PasswordMinLength))

		if len(re.findall(r"[a-z]", password)) < self.PasswordMinLowerCount:
			raise exceptions.WeakPasswordError(
				"Password must contain at least {} lowercase letters.".format(self.PasswordMinLowerCount))

		if len(re.findall(r"[A-Z]", password)) < self.PasswordMinUpperCount:
			raise exceptions.WeakPasswordError(
				"Password must contain at least {} uppercase letters.".format(self.PasswordMinUpperCount))

		if len(re.findall(r"[0-9]", password)) < self.PasswordMinDigitCount:
			raise exceptions.WeakPasswordError(
				"Password must contain at least {} digits.".format(self.PasswordMinDigitCount))

		if len(re.findall(r"[^a-zA-Z0-9]", password)) < self.PasswordMinSpecialCount:
			raise exceptions.WeakPasswordError(
				"Password must contain at least {} special characters.".format(self.PasswordMinSpecialCount))


class PasswordAuthnMethodProvider(AuthnMethodProviderABC):
	MethodType = "password"
	SupportedActions = ["reset"]

	def __init__(self, app, password_service, credentials_service, *args, **kwargs):
		super().__init__(app, *args, **kwargs)
		self.PasswordService = password_service
		self.CredentialsService = credentials_service

	async def iterate_authn_methods(self, credentials_id: str) -> typing.AsyncGenerator[dict, None]:
		"""
		Iterate over active authentication methods for requested credentials. Yield password method if it is active.
		"""
		try:
			yield await self.get_authn_method(credentials_id)
		except KeyError:
			pass

	async def get_authn_method(self, credentials_id: str, method_id: str | None = None) -> dict:
		if method_id is not None:
			raise KeyError("Password is a singleton authentication method; method_id must be None.")

		try:
			credentials = await self.CredentialsService.get(credentials_id, include=["__password"])
		except exceptions.CredentialsNotFoundError:
			raise KeyError()
		if not credentials.get("__password"):
			raise KeyError()
		return {
			"type": "password",
			"label": "Password",
			"cid": credentials_id,
			"actions": self.SupportedActions,
		}
