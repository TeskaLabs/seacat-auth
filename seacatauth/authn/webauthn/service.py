import base64
import logging
import cryptography.hazmat.primitives.hashes

import asab.storage

#

L = logging.getLogger(__name__)

#


class WebAuthnService(asab.Service):
	ChallengeCollection = "wa"

	def __init__(self, app, service_name="seacatauth.WebAuthnService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")

		self.RelyingPartyName = "Seacat Auth"  # TODO: Config
		self.RelyingPartyId = "localhost:8080"  # TODO: Public webui domain
		self.ChallengeTimeout = 60 * 1000  # TODO: Config


	async def _create_registration_challenge(self, credentials_id) -> str:
		raise NotImplementedError("WebAuthnService._create_registration_challenge")


	async def _get_registration_challenge(self, credentials_id) -> str:
		raise NotImplementedError("WebAuthnService._get_registration_challenge")


	async def _create_authentication_challenge(self, credentials_id) -> str:
		raise NotImplementedError("WebAuthnService._create_authentication_challenge")


	async def _get_authentication_challenge(self, credentials_id) -> str:
		raise NotImplementedError("WebAuthnService._get_authentication_challenge")


	async def get_registration_options(self, credentials_id):
		"""
		Prologue to adding WebAuthn to a credentials
		https://www.w3.org/TR/webauthn/#sctn-registering-a-new-credential
		"""

		credentials = await self.CredentialsService.get(credentials_id)

		challenge = await self._create_registration_challenge(credentials_id)

		options = {
			"challenge": challenge,
			"relying_party": {
				"name": self.RelyingPartyName,
				"id": self.RelyingPartyId,
			},
			"user": {
				"id": credentials_id,
				"name": credentials.get("email"),
				"displayName": credentials.get("username"),
				# "icon": icon,  # Optional: URL to user icon
			},
			"parameters": [
				# Supported algorithms
				{"type": "public-key", "alg": cryptography.hazmat.primitives.hashes.SHA256},
				{"type": "public-key", "alg": cryptography.hazmat.primitives.hashes.SHA384},
				{"type": "public-key", "alg": cryptography.hazmat.primitives.hashes.SHA512},
			],
			"timeout": self.ChallengeTimeout,
			"credential_exclude_list": [],
			"attestation": "direct",
		}

		return options


	async def register(self, credentials_id, client_data, attestation_object=None):
		"""
		Add WebAuthn public key to a credentials
		https://www.w3.org/TR/webauthn/#sctn-registering-a-new-credential
		"""

		credentials = await self.CredentialsService.get(credentials_id)

		assert client_data["type"] == "webauthn.create"

		assert client_data["challenge"] == await self._get_registration_challenge(credentials_id)

		assert client_data["origin"] == self.RelyingPartyId

		# TODO: Verify attestation_object
		#   - verify the auth data hash
		#   - check that the user is verified

		public_key = attestation_object.get("public_key")

		# TODO: Update user credentials with the public_key

		return {"result": "OK"}


	async def get_authentication_options(self, credentials_id):
		"""
		Prologue to adding WebAuthn to a credentials
		https://www.w3.org/TR/webauthn/#sctn-verifying-assertion
		"""

		challenge = await self._create_authentication_challenge(credentials_id)

		options = {
			"challenge": challenge,
			"timeout": self.ChallengeTimeout,
			"allow_credentials": [
				{"type": "public-key", "id": base64.urlsafe_b64encode(credentials_id)}
			],
		}

		return options


	def _verify_authentication(self, credentials, authenticator_data, signature):
		raise NotImplementedError("WebAuthnService._verify_authentication")


	async def authenticate(self, credentials_id, client_data, authenticator_data, signature=None):
		"""
		Verify that the user has access to saved WebAuthn credentials
		https://www.w3.org/TR/webauthn/#sctn-verifying-assertion
		"""

		credentials = await self.CredentialsService.get(credentials_id)

		assert client_data["type"] == "webauthn.get"

		assert client_data["challenge"] == await self._get_authentication_challenge(credentials_id)

		assert client_data["origin"] == self.RelyingPartyId

		# TODO: Verify authenticator_data hash

		# TODO: Verify the authenticator_data + signature
		self._verify_authentication(credentials, authenticator_data, signature)

		return {"result": "OK"}
