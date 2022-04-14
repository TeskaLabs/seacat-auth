import base64
import datetime
import json
import logging
import secrets
import urllib.parse

import asab.storage
import pprint
import webauthn
import webauthn.registration
import webauthn.helpers.structs

#

L = logging.getLogger(__name__)

#


class WebAuthnService(asab.Service):
	WebAuthnCredentialCollection = "wa"
	WebAuthnRegistrationChallengeCollection = "warc"

	def __init__(self, app, service_name="seacatauth.WebAuthnService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")

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
			self.RelyingPartyId = str(urllib.parse.urlparse(self.Origin).hostname)

		self.RegistrationTimeout = asab.Config.getseconds("seacatauth:webauthn", "challenge_timeout") * 1000
		self.SupportedAlgorithms = [
			webauthn.helpers.structs.COSEAlgorithmIdentifier(-7)  # Es256
		]

		# TODO: Delete expired challenges
		# TODO: AuthenticationTimeout = login session timeout


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
		async for wa_credential in cursor:
			serial_number = wa_credential.get("sn") + 1
			break
		else:
			serial_number = 1

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


	async def delete_webauthn_credentials_by_user(self, credentials_id: str):
		collection = self.StorageService.Database[self.WebAuthnCredentialCollection]

		query_filter = {"cid": credentials_id}
		result = await collection.delete_many(query_filter)
		L.log(asab.LOG_NOTICE, "WebAuthn credential deleted", struct_data={
			"cid": credentials_id,
			"count": result.deleted_count
		})


	async def create_registration_challenge(self, session_id: str) -> bytes:
		# Delete existing challenge
		try:
			await self.delete_registration_challenge(session_id)
		except KeyError:
			# There is no challenge associated with this user session
			pass

		upsertor = self.StorageService.upsertor(self.WebAuthnRegistrationChallengeCollection, obj_id=session_id)

		expires = datetime.datetime.now() + datetime.timedelta(milliseconds=self.RegistrationTimeout)
		upsertor.set("exp", expires)

		challenge = secrets.token_bytes(32)
		upsertor.set("ch", challenge)

		await upsertor.execute()
		L.log(asab.LOG_NOTICE, "WebAuthn challenge created", struct_data={"sid": session_id})

		return challenge


	async def get_registration_challenge(self, session_id: str) -> bytes:
		challenge_obj = await self.StorageService.get(self.WebAuthnRegistrationChallengeCollection, session_id)
		return challenge_obj["ch"]


	async def delete_registration_challenge(self, session_id: str):
		await self.StorageService.delete(self.WebAuthnRegistrationChallengeCollection, session_id)


	async def create_authentication_challenge(self) -> bytes:
		return secrets.token_bytes(32)


	async def get_registration_options(self, session):
		credentials = await self.CredentialsService.get(session.CredentialsId)
		challenge = await self.create_registration_challenge(session.SessionId)
		options = webauthn.generate_registration_options(
			rp_id=self.RelyingPartyId,
			rp_name=self.RelyingPartyName,
			user_id=session.CredentialsId,
			user_name=credentials.get("email"),
			user_display_name=credentials.get("username"),
			challenge=challenge,
			timeout=self.RegistrationTimeout,
			# authenticator_selection=...,  # Optional
			# exclude_credentials=...,  # Optional
			supported_pub_key_algs=self.SupportedAlgorithms,
		)
		options = webauthn.options_to_json(options)
		return options


	async def register_credential(self, session, public_key_credential: dict):
		# TODO: Support multiple keys per user
		# Only one webauthn key per user is allowed (for now)
		wa_credentials = await self.get_webauthn_credentials_by_user(session.CredentialsId)
		if len(wa_credentials) > 0:
			raise ValueError("WebAuthn credential already registered for this user", {"cid": session.CredentialsId})

		try:
			challenge = await self.get_registration_challenge(session.SessionId)
		except KeyError:
			raise KeyError("Challenge does not exist or timed out", {"sid": session.SessionId})

		_normalize_webauthn_credential_response(public_key_credential)

		registration_credential = webauthn.helpers.structs.RegistrationCredential(
			id=public_key_credential["id"],
			raw_id=public_key_credential["rawId"],
			response=public_key_credential["response"],
			# transports=public_key_credential["transports"],  # Optional
		)
		verified_registration = webauthn.verify_registration_response(
			credential=registration_credential,
			expected_challenge=base64.urlsafe_b64encode(challenge).rstrip(b"="),
			expected_rp_id=self.RelyingPartyId,
			expected_origin=self.Origin,
			# require_user_verification=False,  # Optional
			supported_pub_key_algs=self.SupportedAlgorithms,
			# pem_root_certs_bytes_by_fmt=None,  # Optional
		)

		await self.create_webauthn_credential(
			session.CredentialsId,
			verified_registration.credential_id,
			verified_registration.credential_public_key,
			name=public_key_credential.get("key_name")
		)

		return {"result": "OK"}


	async def get_authentication_options(self, credentials_id: str, timeout: int = None):
		# Only one WebAuthn key supported for now
		wa_credentials = await self.get_webauthn_credentials_by_user(credentials_id)
		wa_credential = wa_credentials[0]
		wcid = wa_credential["_id"]

		allow_credentials = [
			webauthn.helpers.structs.PublicKeyCredentialDescriptor(
				id=wcid,
				# transports=
			)
		]

		if timeout is None:
			timeout = self.RegistrationTimeout

		options = webauthn.generate_authentication_options(
			rp_id=self.RelyingPartyId,
			challenge=await self.create_authentication_challenge(),
			timeout=timeout,
			allow_credentials=allow_credentials,
			user_verification=webauthn.helpers.structs.UserVerificationRequirement.PREFERRED
		)

		options = webauthn.options_to_json(options)
		return options


	async def authenticate_credential(self, credentials_id, authentication_options, public_key_credential):
		"""
		Verify that the user has access to saved WebAuthn credentials
		https://www.w3.org/TR/webauthn/#sctn-verifying-assertion
		"""
		_normalize_webauthn_credential_response(public_key_credential)

		authentication_credential = webauthn.helpers.structs.AuthenticationCredential(
			id=public_key_credential["id"],
			raw_id=public_key_credential["rawId"],
			response=public_key_credential["response"],
		)

		authentication_options = json.loads(authentication_options)
		expected_challenge = authentication_options.get("challenge").encode("ascii")

		# Only one WebAuthn key supported for now
		wa_credentials = await self.get_webauthn_credentials_by_user(credentials_id)
		wa_credential = wa_credentials[0]
		public_key = wa_credential["pk"]
		sign_count = wa_credential["sc"]

		try:
			verified_authentication = webauthn.verify_authentication_response(
				credential=authentication_credential,
				expected_challenge=expected_challenge,
				expected_origin=self.Origin,
				expected_rp_id=self.RelyingPartyId,
				credential_public_key=public_key,
				credential_current_sign_count=sign_count,
				require_user_verification=False,
			)
		except Exception as e:
			L.warning("WebAuthn login failed with {}: {}".format(type(e).__name__, str(e)))
			return False

		# Update sign count in storage
		await self.update_webauthn_credential(
			base64.urlsafe_b64decode(verified_authentication.credential_id + b"=="),
			sign_count=verified_authentication.new_sign_count
		)

		return True


def _normalize_webauthn_credential_response(public_key_credential):
	"""
	In-place modify the WebAuthn response so that it fits the webauthn library methods
	"""
	# Re-encode id, which has been automatically decoded in the handler
	public_key_credential["id"] = base64.urlsafe_b64encode(
		public_key_credential["id"].encode("ascii")).decode("ascii").rstrip("=")
	public_key_credential["rawId"] = public_key_credential["rawId"].encode("ascii")

	# Decode response params
	response = public_key_credential["response"]
	for field in ["clientDataJSON", "authenticatorData", "signature", "attestationObject"]:
		response[field] = base64.urlsafe_b64decode(response[field].encode("ascii") + b"==")
