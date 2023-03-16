import datetime

import pyotp
import logging
import urllib.parse

import asab
import asab.storage

from ..events import EventTypes

#

L = logging.getLogger(__name__)

#


class OTPService(asab.Service):
	TOTPSecretCollection = "tos"

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
		credentials = await self.CredentialsService.get(credentials_id, include=frozenset(["__totp"]))
		secret = credentials.get("__totp")
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


	async def set_totp(self, session, credentials_id, otp):
		"""
		Activates TOTP for the current user, provided that a TOTP secret is already set.
		Requires entering the generated OTP to succeed.
		"""
		credentials = await self.CredentialsService.get(credentials_id, include=frozenset(["__totp"]))
		secret = credentials.get("__totp")
		if secret is not None and len(secret) > 0:
			# TOTP is already enabled
			return {"result": "FAILED"}

		try:
			secret = await self._get_totp_secret(session.SessionId)
		except KeyError:
			# TOTP secret has not been initialized or has expired
			return {"result": "FAILED"}

		totp = pyotp.TOTP(secret)
		if totp.verify(otp) is False:
			# TOTP secret does not match
			return {"result": "FAILED"}

		# Store secret in credentials object
		provider = self.CredentialsService.get_provider(credentials_id)
		await provider.update(credentials_id, {"__totp": secret})
		L.log(asab.LOG_NOTICE, "TOTP secret registered", struct_data={"cid": credentials_id})

		await self._delete_totp_secret(session.SessionId)

		return {"result": "OK"}


	async def unset_totp(self, credentials_id):
		"""
		Deactivates TOTP for the current user and erases the secret.
		"""
		credentials = await self.CredentialsService.get(credentials_id, include=frozenset(["__totp"]))
		secret = credentials.get("__totp")
		if secret is None or len(secret) == 0:
			# TOTP is not active
			return {"result": "FAILED"}

		provider = self.CredentialsService.get_provider(credentials_id)
		await provider.update(credentials_id, {
			"__totp": ""
		})

		return {"result": "OK"}


	async def _create_totp_secret(self, session_id: str) -> str:
		# Delete existing secret
		try:
			await self._get_totp_secret(session_id)
			await self._delete_totp_secret(session_id)
		except KeyError:
			# There is no secret associated with this user session
			pass

		upsertor = self.StorageService.upsertor(self.TOTPSecretCollection, obj_id=session_id)

		expires = datetime.datetime.now(datetime.timezone.utc) + self.RegistrationTimeout
		upsertor.set("exp", expires)

		# TODO: Encryption
		secret = pyotp.random_base32()
		upsertor.set("__s", secret)

		await upsertor.execute(event_type=EventTypes.TOTP_SECRET_CREATED)
		L.log(asab.LOG_NOTICE, "TOTP secret created", struct_data={"sid": session_id})

		return secret


	async def _get_totp_secret(self, session_id: str) -> str:
		data = await self.StorageService.get(self.TOTPSecretCollection, session_id)
		secret = data["__s"]
		exp = data["exp"]
		if exp is None or exp < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("TOTP secret timed out")

		return secret


	async def _delete_totp_secret(self, session_id: str):
		await self.StorageService.delete(self.TOTPSecretCollection, session_id)
		L.info("TOTP secret deleted", struct_data={"sid": session_id})


	async def _delete_expired_totp_secrets(self):
		collection = self.StorageService.Database[self.TOTPSecretCollection]

		query_filter = {"exp": {"$lt": datetime.datetime.now(datetime.timezone.utc)}}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.info("Expired TOTP secrets deleted", struct_data={
				"count": result.deleted_count
			})


def authn_totp(dbcred, credentials):
	try:
		totp = pyotp.TOTP(dbcred['__totp'])
		return totp.verify(credentials['totp'])
	except KeyError:
		return False
