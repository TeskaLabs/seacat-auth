import base64
import hashlib
import logging
import secrets
import struct
import urllib.parse

import cbor2

import cose.algorithms

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

		# TODO: Expire and delete challenges
		self._RegistrationChallenges = {}
		self._AuthenticationChallenges = {}

		self.RelyingPartyName = asab.Config.get("seacatauth:webauthn", "relying_party_name")

		self.RelyingPartyId = asab.Config.get("seacatauth:webauthn", "relying_party_id", fallback=None)
		if self.RelyingPartyId is None:
			auth_webui_base_url = asab.Config.get("general", "auth_webui_base_url")
			self.RelyingPartyId = urllib.parse.urlparse(auth_webui_base_url).hostname

		self.ChallengeTimeout = asab.Config.getseconds("seacatauth:webauthn", "challenge_timeout") * 1000
		self.SupportedAlgorithms = [
			cose.algorithms.Es256
		]


	async def _create_registration_challenge(self, credentials_id) -> str:
		challenge = secrets.token_urlsafe(32)
		challenge_hash = hashlib.md5(challenge.encode()).hexdigest()
		self._RegistrationChallenges[credentials_id] = challenge_hash
		return challenge

	async def _get_registration_challenge(self, credentials_id) -> str:
		return self._RegistrationChallenges.get(credentials_id)


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
			"rp": {
				"name": self.RelyingPartyName,
				"id": self.RelyingPartyId,
			},
			"user": {
				"id": credentials_id,
				"name": credentials.get("email"),
				"displayName": credentials.get("username"),
			},
			"pubKeyCredParams": [
				{"alg": algorithm.identifier, "type": "public-key"}
				for algorithm in self.SupportedAlgorithms
			],
			"timeout": self.ChallengeTimeout,
			# Optional parameters
			# "authenticatorSelection": {
			# 	"authenticatorAttachment": "cross-platform",
			# },
			# "attestation": "direct"
		}

		return options


	async def register(self, credentials_id, client_data, attestation_object=None):
		"""
		Add WebAuthn public key to a credentials
		https://www.w3.org/TR/webauthn/#sctn-registering-a-new-credential
		"""

		credentials = await self.CredentialsService.get(credentials_id, include=frozenset(["__webauthn"]))
		if credentials.get("__webauthn") is not None:
			# WebAuthn key already exists for these credentials
			raise ValueError("WebAuthn key already exists for these credentials")

		# Verify that the correct operation was performed
		assert client_data["type"] == "webauthn.create"

		# Verify that the challenge has not been changed
		assert client_data["challenge"] == await self._get_registration_challenge(credentials_id)

		# Verify the origin
		assert client_data["origin"] == self.RelyingPartyId

		decoded_attestation_object = cbor2.decoder.loads(attestation_object)
		decoded_attestation_object_example = {
			"authData": ...,
			"fmt": "fido-u2f",
			"attStmt": {
				"sig": ...,
				"x5c": ...,
			},
		}

		assert decoded_attestation_object["fmt"] == "fido-u2f"

		# auth-data
		# https://w3c.github.io/webauthn/#authenticator-data
		auth_data = decoded_attestation_object["authData"]
		(
			rp_id_hash,
			flags,
			signature_counter,
			aaguid,
			cid_length
		) = struct.unpack(">32s1sI16sH", auth_data[:55])
		credential_id = auth_data[55:55 + cid_length]
		public_key = auth_data[55 + cid_length:]

		# TODO: Unpack flags
		# TODO: Check that the user is verified

		# TODO: Validate the auth data hash

		# Update user credentials with the public_key
		provider = self.CredentialsService.get_provider(credentials_id)
		provider.update(credentials_id, {"__webauthn": public_key})

		return {"result": "OK"}


	async def get_authentication_options(self, credentials_id):
		"""
		Prologue to adding WebAuthn to a credentials
		https://www.w3.org/TR/webauthn/#sctn-verifying-assertion
		"""

		# TODO: Authentication will use the main login-prologue challenge instead
		challenge = await self._create_authentication_challenge(credentials_id)

		options = {
			"challenge": challenge,
			"timeout": self.ChallengeTimeout,
			"allow_credentials": [
				{"type": "public-key", "id": base64.urlsafe_b64encode(credentials_id)}
			],
		}

		return options


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


	def _verify_authentication(self, credentials, authenticator_data, signature):
		raise NotImplementedError("WebAuthnService._verify_authentication")
