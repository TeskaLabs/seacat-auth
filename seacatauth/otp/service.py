import datetime

import pyotp
import logging
import urllib.parse

import asab
import asab.storage

from typing import Optional

#

L = logging.getLogger(__name__)

#


class EventType():
	TOTP_CREATED = "totp_created"
	TOTP_MOVED_TO_TOTP_COLLECTION = "totp_moved_to_its_collection"


class OTPService(asab.Service):
	TOTPUnregisteredSecretCollection = "tos"
	TOTPCollection = "totp"

	def __init__(self, app, service_name="seacatauth.OTPService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.Issuer = asab.Config.get("seacatauth:otp", "issuer")
		if len(self.Issuer) == 0:
			auth_webui_base_url = asab.Config.get("general", "auth_webui_base_url")
			self.Issuer = str(urllib.parse.urlparse(auth_webui_base_url).hostname)
		self.RegistrationTimeout = datetime.timedelta(
			seconds=asab.Config.getseconds("seacatauth:otp", "registration_timeout")
		)

		app.PubSub.subscribe("Application.tick/60!", self._on_tick)


	async def _on_tick(self, event_name):
		await self._delete_expired_totp_secrets()





	async def get_totp_secret(self, session, credentials_id):
		"""
		Returns the status of TOTP setting.
		If not activated, it also generates and returns a new TOTP secret.
		"""
		L.warning("ENTERED get_totp_secret({}, {})".format(session, credentials_id))
		credentials = await self.CredentialsService.get(credentials_id, include=frozenset(["__totp"]))
		secret = credentials.get("__totp")
		L.warning("credentials: {}".format(credentials))
		L.warning("secret = {}".format(secret))
		if secret is not None and len(secret) > 0:
			return {
				"result": "OK",
				"active": True
			}

		# Generate secret and store in database
		secret = await self._create_totp_secret(session.SessionId)

		username = credentials["username"]

		url = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=self.Issuer)

		response = {
			"result": "OK",
			"active": False,
			"url": url,
			"username": username,
			"issuer": self.Issuer,
			"secret": secret,
			"timeout": self.RegistrationTimeout.total_seconds(),
		}
		return response


	async def complete_totp_registration(self, session, credentials_id, otp):
		"""
		Activates TOTP for the current user, provided that a TOTP secret is already set.
		Requires entering the generated OTP to succeed.
		"""
		if not await self.has_activated_totp(credentials_id):
			L.warning("self.has_activated_totp = False")
			L.warning("result: FAILED")
			return {"result": "FAILED"}

		try:
			secret = await self._get_totp_secret_from_session_id(session.SessionId)
		except KeyError:
			# TOTP secret has not been initialized or has expired
			return {"result": "FAILED"}

		totp = pyotp.TOTP(secret)
		if totp.verify(otp) is False:
			# TOTP secret does not match
			return {"result": "FAILED"}

		# Store secret in its own dedicated collection
		upsertor = self.StorageService.upsertor(collection=self.TOTPCollection, obj_id=credentials_id)
		upsertor.set("__totp", secret)
		await upsertor.execute(custom_data={"event_type": EventType.TOTP_MOVED_TO_TOTP_COLLECTION})
		# provider = self.CredentialsService.get_provider(credentials_id)
		# await provider.update(credentials_id, {"__totp": secret})
		L.log(asab.LOG_NOTICE, "TOTP secret registered", struct_data={"cid": credentials_id})

		await self._delete_totp_secret(session.SessionId)

		return {"result": "OK"}


	async def unset_totp(self, credentials_id: str):
		"""
		Deactivates TOTP for the current user and erases the secret.
		"""
		if not await self.has_activated_totp(credentials_id):
			return {"result": "FAILED"}

		provider = self.CredentialsService.get_provider(credentials_id)
		await provider.update(credentials_id, {
			"__totp": ""
		})

		return {"result": "OK"}


	async def _create_totp_secret(self, session_id: str) -> str:
		"""
		Create TOTP secret.
		"""
		L.warning("ENTERED 133 FUNCTION _create_totp_secret(session_id={})".format(session_id))
		# Delete secret if exists.
		try:
			await self._delete_totp_secret(session_id)
		except KeyError:
			# There is no secret associated with this user session
			pass

		upsertor = self.StorageService.upsertor(collection=self.TOTPUnregisteredSecretCollection, obj_id=session_id)

		expires: datetime.datetime = datetime.datetime.now(datetime.timezone.utc) + self.RegistrationTimeout
		upsertor.set("exp", expires)

		# TODO: Encryption
		secret = pyotp.random_base32()
		upsertor.set("__s", secret)

		await upsertor.execute(custom_data={"event_type": EventType.TOTP_CREATED})
		L.log(asab.LOG_NOTICE, "TOTP secret created", struct_data={"sid": session_id})

		return secret


	async def _get_totp_secret_from_session_id(self, session_id: str) -> str:
		"""
		Get TOTP secret from TOTPUnregisteredSecretCollection["__s"]. If it has already expired, raise KeyError.
		"""
		L.warning("ENTERING 161 _get_totp_secret_from_session_id({})".format(session_id))
		data = await self.StorageService.get(collection=self.TOTPUnregisteredSecretCollection, obj_id=session_id)
		secret: str = data["__s"]
		expiration_time: Optional[datetime.datetime] = data["exp"]
		if expiration_time is None or expiration_time < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("TOTP secret timed out")
		L.warning("secret: {}".format(secret))
		return secret

	async def _get_totp_secret_from_credentials_id(self, credentials_id: str) -> str:
		"""
		Get TOTP secret from TOTPCollection["__totp"].
		"""
		L.warning("ENTERING 174 _get_totp_secret_from_credentials_id({})".format(credentials_id))
		try:
			credentials = await self.StorageService.get(collection=self.TOTPCollection, obj_id=credentials_id)
			L.warning("credentials: {}".format(credentials))
			secret: str = credentials.get("__totp")
			L.warning("secret = {}".format(secret))
		except KeyError:
			L.warning("key error in obtaining credentials -> secret = None")
			secret = None
		return secret

	async def _delete_totp_secret(self, session_id: str):
		await self.StorageService.delete(collection=self.TOTPUnregisteredSecretCollection, obj_id=session_id)
		L.info("TOTP secret deleted", struct_data={"sid": session_id})


	async def _delete_expired_totp_secrets(self):
		collection = self.StorageService.Database[self.TOTPUnregisteredSecretCollection]

		query_filter = {"exp": {"$lt": datetime.datetime.now(datetime.timezone.utc)}}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.info("Expired TOTP secrets deleted", struct_data={
				"count": result.deleted_count
			})

	async def has_activated_totp(self, credentials_id: str) -> bool:
		"""
		Check if the user has TOTP activated from TOTPCollection. (For backward compatibility: check also TOTPUnregisteredSecretCollection.)
		"""
		L.warning("ENTERING 192: has_activated_totp")
		secret: Optional[str] = await self._get_totp_secret_from_credentials_id(credentials_id)
		L.warning("secret = {}".format(secret))
		if secret is None:
			# look for secret in TOTPUnregisteredSecretCollection
			L.warning("looking for it in TOTPUnregisteredSecretCollection['__totp']")
			credentials = await self.CredentialsService.get(credentials_id, include=frozenset(["__totp"]))
			secret = credentials.get("__totp")
			L.warning("secret = {}".format(secret))

		if secret is not None and len(secret) > 0:
			return True
		return False


	async def compare_totp_with_request_data(self, credentials_id, request_data: dict) -> bool:
		L.warning("ENTERING 208 compare_totp_with_request_data({}, {})".format(credentials_id, request_data))
		totp_secret: Optional[str] = await self._get_totp_secret_from_credentials_id(credentials_id)
		L.warning("totp_secret = {}".format(totp_secret))
		if totp_secret is None:
			# look for secret in TOTPUnregisteredSecretCollection
			credentials = await self.CredentialsService.get(credentials_id, include=frozenset(["__totp"]))
			totp_secret = credentials.get("__totp")
			L.warning("totp_secret from CredentialService = {}".format(totp_secret))

		try:
			totp_object = pyotp.TOTP(totp_secret)
			return totp_object.verify(request_data['totp'])
		except KeyError:
			return False
