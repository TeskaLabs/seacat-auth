import base64
import hashlib
import logging
import secrets
import struct
import urllib.parse

import cbor2

import cose.algorithms

import asab.storage
import pprint

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

		# RP ID must match host's domain name (without scheme, port or subpath)
		# https://www.w3.org/TR/webauthn-2/#relying-party-identifier
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

	async def _verify_registration_challenge(self, credentials_id, challenge) -> str:
		challenge_hash = hashlib.md5(challenge.encode()).hexdigest()
		return challenge_hash == self._RegistrationChallenges.get(credentials_id)

	async def _create_authentication_challenge(self, credentials_id) -> str:
		challenge = secrets.token_urlsafe(32)
		challenge_hash = hashlib.md5(challenge.encode()).hexdigest()
		self._AuthenticationChallenges[credentials_id] = challenge_hash
		return challenge

	async def _verify_authentication_challenge(self, credentials_id, challenge) -> str:
		challenge_hash = hashlib.md5(challenge.encode()).hexdigest()
		return challenge_hash == self._AuthenticationChallenges.get(credentials_id)


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


	async def register_key(self, credentials_id, client_data, attestation_object=None):
		"""
		Add WebAuthn public key to a credentials
		https://www.w3.org/TR/webauthn/#sctn-registering-a-new-credential

		client_data_example = {
			'challenge': 'MEtoY3BPemkyaWJQeTByM2tLWE1pekdaa3U0OGRLVXZTNm51UUVmWXdxRQ',
			'clientExtensions': {},
			'hashAlgorithm': 'SHA-256',
			'origin': 'https://localhost:3000',
			'type': 'webauthn.create'
		}

		attestation_object_example = {
			'attStmt': {},
			'authData': b'I\x96\r\xe5\x88\x0e\x8cht4\x17\x0fdv`[\x8f\xe4\xae\xb9' ... ,
			'fmt': 'none'
		}
		"""

		credentials = await self.CredentialsService.get(credentials_id, include=frozenset(["__webauthn"]))
		if credentials.get("__webauthn") not in (None, ""):
			return {
				"result": "ALREADY-EXISTS",
				"description": "WebAuthn key already registered for these credentials."
			}

		# Verify that the correct operation was performed
		assert client_data["type"] == "webauthn.create"

		# Verify that the challenge has not been changed
		challenge = base64.b64decode(client_data["challenge"].encode("ascii") + b"==").decode()
		assert await self._verify_registration_challenge(credentials_id, challenge)

		# Verify the origin
		origin_hostname = urllib.parse.urlparse(client_data["origin"]).hostname
		assert origin_hostname == self.RelyingPartyId

		attestation_object = cbor2.decoder.loads(attestation_object)

		# TODO: Check attestation format
		assert attestation_object["fmt"] in frozenset([
			"packed", "tpm", "android-key", "android-safetynet", "none", "fido-u2f", "apple"
		])

		# TODO: Check attestation statement depending on the format

		# auth-data
		# https://w3c.github.io/webauthn/#authenticator-data
		auth_data = attestation_object["authData"]
		(
			rp_id_hash,
			flags,
			signature_counter,
			aaguid,
			cid_length
		) = struct.unpack(">32s1sI16sH", auth_data[:55])
		webauthn_cid = auth_data[55:55 + cid_length]
		public_key = auth_data[55 + cid_length:]

		# public_key is a CBOR-encoded object
		# cbor2.decoder.loads(public_key)

		# Unpack flags
		flags = [bool(int(i)) for i in format(ord(flags), "08b")]
		(
			extension_data_included,
			attested_credential_data_included,
			_, _, _,  # Bits reserved for future use
			user_verified,
			_,  # Bit reserved for future use
			user_present
		) = flags

		assert user_present

		# TODO: User verification
		# assert user_verified

		# TODO: Validate the auth data hash

		# Update user credentials with the public_key
		provider = self.CredentialsService.get_provider(credentials_id)
		result = await provider.update(credentials_id, {
			"__webauthn": {
				"key": public_key,
				"cid": webauthn_cid,
			}
		})
		if result == "OK":
			return {"result": result}
		else:
			return result


	async def remove_key(self, credentials_id):
		provider = self.CredentialsService.get_provider(credentials_id)
		result = await provider.update(credentials_id, {"__webauthn": ""})
		if result == "OK":
			return {"result": result}
		else:
			return result


	async def get_authentication_options(self, credentials_id: str):
		"""
		Prologue to adding WebAuthn to a credentials
		https://www.w3.org/TR/webauthn/#sctn-verifying-assertion
		"""
		credentials = await self.CredentialsService.get(credentials_id, include=frozenset(["__webauthn"]))
		L.warning(f"\n🐱 {pprint.pformat(credentials['__webauthn'])}")
		webauthn_cid = credentials["__webauthn"]["cid"]

		challenge = await self._create_authentication_challenge(credentials_id)

		options = {
			"challenge": challenge,
			"timeout": self.ChallengeTimeout,
			"allowCredentials": [
				{
					"type": "public-key",
					"id": base64.urlsafe_b64encode(webauthn_cid).decode(),
					# "transports": ['usb', 'ble', 'nfc'],  # Optional
				}
			],
		}

		return options


	async def authenticate_key(self, credentials_id, client_data, authenticator_data, signature=None):
		"""
		Verify that the user has access to saved WebAuthn credentials
		https://www.w3.org/TR/webauthn/#sctn-verifying-assertion
		"""

		return True

		credentials = await self.CredentialsService.get(credentials_id)

		assert client_data["type"] == "webauthn.get"

		challenge = base64.b64decode(client_data["challenge"].encode("ascii") + b"==").decode()
		await self._verify_authentication_challenge(credentials_id, challenge)

		origin_hostname = urllib.parse.urlparse(client_data["origin"]).hostname
		assert origin_hostname == self.RelyingPartyId

		# TODO: Verify authenticator_data hash

		# TODO: Verify the authenticator_data + signature
		self._verify_authentication(credentials, authenticator_data, signature)

		return {"result": "OK"}


	def _verify_authentication(self, credentials, authenticator_data, signature):
		raise NotImplementedError("WebAuthnService._verify_authentication")
