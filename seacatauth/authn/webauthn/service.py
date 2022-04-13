import base64
import hashlib
import json
import logging
import secrets
import struct
import urllib.parse

import cbor2

import cose.algorithms

import asab.storage
import pprint
import webauthn
import webauthn.helpers.structs

#

L = logging.getLogger(__name__)

#


class WebAuthnService(asab.Service):
	WebAuthnCredentialCollection = "wa"

	def __init__(self, app, service_name="seacatauth.WebAuthnService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")

		# TODO: Expire and delete challenges
		self._RegistrationChallenges = {}
		self._AuthenticationChallenges = {}

		self.RelyingPartyName = asab.Config.get("seacatauth:webauthn", "relying_party_name")

		self.Origin = asab.Config.get("seacatauth:webauthn", "origin", fallback=None)
		if self.Origin is None:
			auth_webui_base_url = asab.Config.get("general", "auth_webui_base_url")
			parsed = urllib.parse.urlparse(auth_webui_base_url)
			self.Origin = "{}://{}".format(parsed.scheme, parsed.netloc)

		# RP ID must match host's domain name (without scheme, port or subpath)
		# https://www.w3.org/TR/webauthn-2/#relying-party-identifier
		self.RelyingPartyId = asab.Config.get("seacatauth:webauthn", "relying_party_id", fallback=None)
		if self.RelyingPartyId is None:
			self.RelyingPartyId = urllib.parse.urlparse(self.Origin).hostname

		self.ChallengeTimeout = asab.Config.getseconds("seacatauth:webauthn", "challenge_timeout") * 1000
		self.SupportedAlgorithms = [
			cose.algorithms.Es256
		]


	async def create_webauthn_credential(
		self,
		credentials_id: str,
		webauthn_credential_id: bytes,
		public_key: bytes,
		name: str = None
	):
		# Get the serial number of this user's most recent webauthn credential
		collection = self.StorageService.Database[self.WebAuthnCredentialCollection]
		cursor = collection.find()
		cursor.sort("sn", 1)
		cursor.limit(1)
		newest_wa_credential = await anext(cursor)
		serial_number = newest_wa_credential.get("sn") + 1

		if name is None:
			name = "Key_{}".format(serial_number)

		upsertor = self.StorageService.upsertor(self.WebAuthnCredentialCollection, obj_id=webauthn_credential_id)

		upsertor.set("pk", public_key)
		upsertor.set("cid", credentials_id)
		upsertor.set("sc", 0)  # Sign counter
		upsertor.set("sn", serial_number)
		upsertor.set("name", name)

		wcid = await upsertor.execute()
		L.log(asab.LOG_NOTICE, "WebAuthn credential created", struct_data={"wcid": wcid})


	async def get_webauthn_credential(self, webauthn_credential_id):
		return await self.StorageService.get(self.WebAuthnCredentialCollection, webauthn_credential_id)


	async def get_webauthn_credentials_by_user(self, credentials_id: str):
		collection = self.StorageService.Database[self.WebAuthnCredentialCollection]

		query_filter = {"cid": credentials_id}
		cursor = collection.find(query_filter)

		cursor.sort("_c", -1)

		wa_credentials = []
		async for resource_dict in cursor:
			wa_credentials.append(resource_dict)

		return wa_credentials


	async def update_webauthn_credential(
		self, webauthn_credential_id: bytes,
		sign_count: int = None,
		name: str = None
	):
		"""
		Only allows updating the key name and the sign count (for now).
		"""
		wa_credential = await self.get_webauthn_credential(webauthn_credential_id)

		upsertor = self.StorageService.upsertor(
			self.WebAuthnCredentialCollection,
			obj_id=webauthn_credential_id,
			version=wa_credential["_v"]
		)

		if sign_count is not None:
			upsertor.set("sc", sign_count)

		if name is not None:
			upsertor.set("name", name)

		await upsertor.execute()
		L.log(asab.LOG_NOTICE, "WebAuthn credential updated", struct_data={
			"wcid": webauthn_credential_id,
		})


	async def delete_webauthn_credential(self, webauthn_credential_id: bytes):
		await self.StorageService.delete(self.WebAuthnCredentialCollection, webauthn_credential_id)
		L.log(asab.LOG_NOTICE, "WebAuthn credential deleted", struct_data={"wcid": webauthn_credential_id})


	def _get_registration_challenge(self, session) -> bytes:
		return hashlib.md5(session.SessionId.encode("ascii")).digest()


	async def _get_authentication_challenge(self) -> bytes:
		return secrets.token_bytes(32)


	async def get_registration_options(self, session):
		"""
		Prologue to adding WebAuthn to a credentials
		https://www.w3.org/TR/webauthn/#sctn-registering-a-new-credential
		"""

		credentials = await self.CredentialsService.get(session.CredentialsId)

		challenge = self._get_registration_challenge(session)

		options = {
			"challenge": challenge,
			"rp": {
				"name": self.RelyingPartyName,
				"id": self.RelyingPartyId,
			},
			"user": {
				"id": session.CredentialsId,
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


	async def register_key(self, session, public_key_credential: dict):
		"""
		Add WebAuthn public key to a credentials
		https://www.w3.org/TR/webauthn/#sctn-registering-a-new-credential
		"""

		credentials = await self.CredentialsService.get(session.CredentialsId, include=frozenset(["__webauthn"]))
		if credentials.get("__webauthn") not in (None, ""):
			return {
				"result": "ALREADY-EXISTS",
				"description": "WebAuthn key already registered for these credentials."
			}

		assert public_key_credential["type"] == "public-key"

		# Parse the client data
		client_data = json.loads(
			base64.urlsafe_b64decode(
				public_key_credential["response"]["clientDataJSON"].encode("ascii") + b"=="
			).decode()
		)
		# client_data_example = {
		# 	'challenge': 'MEtoY3BPemkyaWJQeTByM2tLWE1pekdaa3U0OGRLVXZTNm51UUVmWXdxRQ',
		# 	'clientExtensions': {},
		# 	'hashAlgorithm': 'SHA-256',
		# 	'origin': 'https://localhost:3000',
		# 	'type': 'webauthn.create'
		# }

		attestation_object = base64.urlsafe_b64decode(
			public_key_credential["response"]["attestationObject"].encode("ascii") + b"=="
		)
		# attestation_object_example = {
		# 	'attStmt': {},
		# 	'authData': b'I\x96\r\xe5\x88\x0e\x8cht4\x17\x0fdv`[\x8f\xe4\xae\xb9'...,
		# 	'fmt': 'none'
		# }

		# Verify that the correct operation was performed
		assert client_data["type"] == "webauthn.create"

		# Verify that the challenge has not been changed
		challenge = base64.b64decode(client_data["challenge"].encode("ascii") + b"==").decode()
		assert challenge == self._get_registration_challenge(session)

		# Verify the origin
		origin_hostname = urllib.parse.urlparse(client_data["origin"]).hostname
		assert origin_hostname == self.RelyingPartyId

		attestation_object = cbor2.decoder.loads(attestation_object)
		L.warning(f"\n🐞 ATT OBJ {pprint.pformat(attestation_object)}")

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
		) = struct.unpack(">32s1sI", auth_data[:37])

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

		if attested_credential_data_included:
			aaguid, cid_length = struct.unpack(">16sH", auth_data[37:55])
			webauthn_cid = auth_data[55:55 + cid_length]
			public_key = auth_data[55 + cid_length:]
		else:
			L.error("attested_credential_data_included is False")
			return {"result": "FAILED"}

		data = {
			"rp_id_hash": rp_id_hash,
			"signature_counter": signature_counter,
			"aaguid": aaguid,
			"cid_length": cid_length,
			"webauthn_cid": webauthn_cid.hex(),
			"public_key": public_key.hex()
		}
		L.warning(f"\n🐞 DATA {pprint.pformat(data)}")


		# Verify that the ids match
		# assert base64.urlsafe_b64encode(webauthn_cid + b'==') == public_key_credential["id"]

		# public_key is a CBOR-encoded object
		# cbor2.decoder.loads(public_key)


		assert user_present

		# TODO: User verification
		# assert user_verified

		# TODO: Validate the auth data hash
		webauthn_cid_encoded = base64.urlsafe_b64encode(webauthn_cid)
		L.warning(
			f"\n🔑ID {public_key_credential['id']}\n🔑ID {public_key_credential['rawId']}"
			f"\n🔑ID {webauthn_cid}"
			f"\n🔑ID {webauthn_cid_encoded}"
		)

		await self.create_webauthn_credential(
			session.CredentialsId,
			webauthn_cid,
			public_key,
			name=public_key_credential.get("key_name")
		)
		# Update user credentials with the public_key
		provider = self.CredentialsService.get_provider(session.CredentialsId)
		result = await provider.update(session.CredentialsId, {
			"__webauthn": {
				"key": public_key,
				"cid": webauthn_cid,
				# "cid": public_key_credential["id"],
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
		credentials = await self.CredentialsService.get(credentials_id, include=frozenset(["__webauthn"]))
		webauthn_cid = credentials["__webauthn"]["cid"]
		allow_credentials = [
			webauthn.helpers.structs.PublicKeyCredentialDescriptor(
				id=webauthn_cid,
				# transports=
			)
		]

		options = webauthn.generate_authentication_options(
			rp_id=self.RelyingPartyId,
			challenge=await self._create_authentication_challenge(credentials_id),
			timeout=self.ChallengeTimeout,
			allow_credentials=allow_credentials,
			user_verification=webauthn.helpers.structs.UserVerificationRequirement.PREFERRED
		)

		options = webauthn.options_to_json(options)
		L.warning(f"\n🔑AUTH OPTS {pprint.pformat(options)}")
		return options


	async def authenticate_key(self, credentials_id, authentication_options, public_key_credential):
		"""
		Verify that the user has access to saved WebAuthn credentials
		https://www.w3.org/TR/webauthn/#sctn-verifying-assertion
		"""
		response = public_key_credential["response"]
		response["clientDataJSON"] = base64.urlsafe_b64decode(response["clientDataJSON"].encode("ascii") + b"==")
		response["authenticatorData"] = base64.urlsafe_b64decode(response["authenticatorData"].encode("ascii") + b"==")
		response["signature"] = base64.urlsafe_b64decode(response["signature"].encode("ascii") + b"==")

		authentication_credential = webauthn.helpers.structs.AuthenticationCredential(
			id=base64.urlsafe_b64encode(public_key_credential["id"].encode("ascii")).decode("ascii").rstrip("="),
			raw_id=public_key_credential["rawId"].encode("ascii"),
			response=response,
		)

		authentication_options = json.loads(authentication_options)

		credentials = await self.CredentialsService.get(credentials_id, include=frozenset(["__webauthn"]))
		L.warning(f"\n🧟 credentials {pprint.pformat(credentials)}")
		L.warning(f"\n🔐 public_key_credential {pprint.pformat(public_key_credential)}")
		L.warning(f"\n📲 authentication_options {pprint.pformat(authentication_options)}")
		clientDataJSON = webauthn.helpers.parse_client_data_json(response["clientDataJSON"])
		expected_challenge = authentication_options.get("challenge").encode("ascii")
		L.warning(f"\n🌾 clientDataJSON {pprint.pformat(clientDataJSON)}")
		L.warning(f"\n⛰ expected_challenge {pprint.pformat(expected_challenge)}")
		try:
			verified_authentication = webauthn.verify_authentication_response(
				credential=authentication_credential,
				expected_challenge=expected_challenge,
				expected_origin=self.Origin,
				expected_rp_id=self.RelyingPartyId,
				credential_public_key=credentials["__webauthn"]["key"],
				credential_current_sign_count=0,  # TODO: Get from mongo
				require_user_verification=False,
			)
		except ... as e:
			L.warning("Login failed with {}: {}".format(type(e).__name__, str(e)))
			return False

		# TODO: Update count in mongo coll
		verified_authentication.new_sign_count

		verified_authentication.credential_id  # This will be mongo ID

		return True


	def _verify_authentication(self, credentials, authenticator_data, signature):
		raise NotImplementedError("WebAuthnService._verify_authentication")
