import datetime

import pyotp
import logging

import asab
import asab.storage

#

L = logging.getLogger(__name__)

#


class OTPService(asab.Service):
	def __init__(self, app, service_name="seacatauth.OTPService"):
		super().__init__(app, service_name)
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.Issuer = asab.Config.get("seacatauth:otp", "issuer")
		self.SecretExpiration = datetime.timedelta(
			seconds=asab.Config.getseconds("seacatauth:otp", "setup_expiration")
		)

		# Temporary storage for otp secrets that haven't been activated yet
		self.Secrets = {}

		app.PubSub.subscribe("Application.tick/60!", self._on_tick)

	async def _on_tick(self, event_name):
		self.delete_expired_secrets()

	async def get_totp(self, session, credentials_id):
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

		# generate secret and store in memory
		secret = pyotp.random_base32()
		self.Secrets[session.SessionId] = {
			"secret": secret,
			"expires": datetime.datetime.utcnow() + self.SecretExpiration
		}

		username = credentials["username"]

		url = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=self.Issuer)

		response = {
			"result": "OK",
			"active": False,
			"url": url,
			"username": username,
			"issuer": self.Issuer,
			"secret": secret
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

		secret = self.Secrets.get(session.SessionId)["secret"]
		if secret is None:
			# TOTP secret has not been initialized
			return {"result": "FAILED"}

		totp = pyotp.TOTP(secret)
		if totp.verify(otp) is False:
			# TOTP secret does not match
			return {"result": "FAILED"}

		# Store secret in credentials object
		provider = self.CredentialsService.get_provider(credentials_id)
		await provider.update(credentials_id, {"__totp": secret})

		# Delete secret from memory
		del self.Secrets[session.SessionId]

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

	def delete_expired_secrets(self):
		secrets_to_delete = []
		now = datetime.datetime.utcnow()
		for sid, data in self.Secrets.items():
			if data["expires"] < now:
				secrets_to_delete.append(sid)
		for sid in secrets_to_delete:
			del self.Secrets[sid]


def authn_totp(dbcred, credentials):
	try:
		totp = pyotp.TOTP(dbcred['__totp'])
		return totp.verify(credentials['totp'])
	except KeyError:
		return False
