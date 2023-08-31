import base64
import datetime
import json
import logging
import secrets
import typing
import urllib.parse
import re

import aiohttp
import asab.storage
import jwcrypto.jwt
import jwcrypto.jwk
import webauthn
import webauthn.registration
import webauthn.helpers.structs
import cryptography.hazmat.primitives.serialization
import cryptography.x509

from ...events import EventTypes
#

L = logging.getLogger(__name__)

#


class WebAuthnService(asab.Service):
	WebAuthnCredentialCollection = "wa"
	WebAuthnRegistrationChallengeCollection = "warc"
	FidoMetadataServiceUrl = "https://mds3.fidoalliance.org"

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

		self.KeyNameRegex = re.compile(r"^[a-z][a-z0-9._-]{0,128}[a-z0-9]$")

		self.FidoMetadata: typing.Dict[str, dict] | None = None

		app.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)


	async def initialize(self, app):
		await self._load_fido_metadata()


	async def _on_housekeeping(self, event_name):
		await self._delete_expired_challenges()


	async def _load_fido_metadata(self, speculative=True):
		if speculative and self.FidoMetadata is not None:
			return
		# FIXME: try/except
		async with aiohttp.ClientSession() as session:
			async with session.get(self.FidoMetadataServiceUrl) as resp:
				if resp.status != 200:
					text = await resp.text()
					L.error("Failed to fetch FIDO metadata:\n{}".format(text[:1000]))
					return
				jwt = await resp.text()
		jwt = jwcrypto.jwt.JWT(jwt=jwt)
		cert_chain = jwt.token.jose_header.get("x5c", [])
		leaf_cert = cryptography.x509.load_der_x509_certificate(base64.b64decode(cert_chain[0]))
		public_key = leaf_cert.public_key()
		public_key = public_key.public_bytes(
			cryptography.hazmat.primitives.serialization.Encoding.PEM,
			cryptography.hazmat.primitives.serialization.PublicFormat.PKCS1)
		public_key = jwcrypto.jwk.JWK.from_pem(public_key)
		jwt.validate(public_key)
		entries = json.loads(jwt.claims)["entries"]
		# FIDO2 authenticators are identified with AAGUID
		self.FidoMetadata = {
			int(entry["aaguid"].replace("-", ""), 16): entry["metadataStatement"]
			for entry in entries
			if "aaguid" in entry}


	async def create_webauthn_credential(
		self,
		credentials_id: str,
		verified_registration,  # webauthn.registration.VerifiedRegistration
		name: str = None
	):
		"""
		Create database entry for a verified WebAuthn credential
		"""
		await self._load_fido_metadata()
		aaguid = int(verified_registration.aaguid.replace("-", ""), 16)
		if aaguid == 0:
			# FIXME: Identify using attestationCertificateKeyIdentifiers
			#   https://fidoalliance.org/fido-technotes-the-truth-about-attestation/
			metadata = None
		else:
			metadata = self.FidoMetadata.get(aaguid)

		if name is None:
			if metadata is not None:
				name = metadata["description"]
			else:
				name = "key-{}".format(datetime.datetime.now(datetime.timezone.utc).strftime("%y%m%d-%H%M%S"))
		else:
			if self.KeyNameRegex.fullmatch(name) is None:
				raise ValueError("Invalid WebAuthn credential name", {"name": name})

		upsertor = self.StorageService.upsertor(
			self.WebAuthnCredentialCollection,
			obj_id=verified_registration.credential_id
		)

		upsertor.set("pk", verified_registration.credential_public_key)
		upsertor.set("cid", credentials_id)
		upsertor.set("sc", verified_registration.sign_count)
		upsertor.set("aa", verified_registration.aaguid)
		upsertor.set("fmt", verified_registration.fmt.value)
		upsertor.set("uv", verified_registration.user_verified)
		upsertor.set("ct", verified_registration.credential_type.value)
		upsertor.set("ao", verified_registration.attestation_object)
		upsertor.set("rpid", self.RelyingPartyId)
		upsertor.set("name", name)
		if metadata:
			# FIXME: Do we need to store all the metadata?
			upsertor.set("md", metadata)

		wacid = await upsertor.execute(event_type=EventTypes.WEBAUTHN_CREDENTIALS_CREATED)
		L.log(asab.LOG_NOTICE, "WebAuthn credential created", struct_data={"wacid": wacid.hex()})


	async def get_webauthn_credential(self, webauthn_credential_id):
		"""
		Get WebAuthn credential detail by its ID
		"""
		return await self.StorageService.get(self.WebAuthnCredentialCollection, webauthn_credential_id)


	async def list_webauthn_credentials(self, credentials_id: str):
		"""
		Get all WebAuthn credentials associated with specific SCA credentials
		"""
		collection = self.StorageService.Database[self.WebAuthnCredentialCollection]

		query_filter = {
			"cid": credentials_id,
			"rpid": self.RelyingPartyId,  # For verification, to prevent incompatible (migrated) credentials
		}
		cursor = collection.find(query_filter)

		cursor.sort("_c", -1)

		wa_credentials = []
		async for resource_dict in cursor:
			wa_credentials.append(resource_dict)

		return wa_credentials


	async def update_webauthn_credential(
		self, webauthn_credential_id: bytes, *,
		credentials_id: str = None,
		sign_count: int = None,
		name: str = None,
		last_login: datetime.datetime = None,
	):
		"""
		Update WebAuthn credential

		Only allows updating key name, last login time and sign count.

		If credentials_id is specified, ensure that it matches the database entry.
		"""
		wa_credential = await self.get_webauthn_credential(webauthn_credential_id)

		if credentials_id is not None:
			if credentials_id != wa_credential["cid"]:
				raise KeyError("WebAuthn credential not found", {
					"wacid": webauthn_credential_id,
					"cid": credentials_id
				})

		upsertor = self.StorageService.upsertor(
			self.WebAuthnCredentialCollection,
			obj_id=webauthn_credential_id,
			version=wa_credential["_v"]
		)

		if sign_count is not None:
			upsertor.set("sc", sign_count)

		if name is not None:
			upsertor.set("name", name)

		if last_login is not None:
			upsertor.set("ll", last_login)

		await upsertor.execute(event_type=EventTypes.WEBAUTHN_CREDENTIALS_UPDATED)
		L.log(asab.LOG_NOTICE, "WebAuthn credential updated", struct_data={
			"wacid": webauthn_credential_id.hex(),
		})


	async def delete_webauthn_credential(self, webauthn_credential_id: bytes, credentials_id: str = None):
		"""
		Delete WebAuthn credential by its ID.

		If credentials_id is specified, ensure that it matches the database entry.
		"""

		if credentials_id is not None:
			wa_credential = await self.get_webauthn_credential(webauthn_credential_id)
			if credentials_id != wa_credential["cid"]:
				raise KeyError("WebAuthn credential not found", {
					"wacid": webauthn_credential_id,
					"cid": credentials_id
				})

		await self.StorageService.delete(self.WebAuthnCredentialCollection, webauthn_credential_id)
		L.log(asab.LOG_NOTICE, "WebAuthn credential deleted", struct_data={"wacid": webauthn_credential_id.hex()})


	async def delete_all_webauthn_credentials(self, credentials_id: str):
		"""
		Delete all WebAuthn credentials associated with specific SCA credentials
		"""
		collection = self.StorageService.Database[self.WebAuthnCredentialCollection]

		query_filter = {"cid": credentials_id}
		result = await collection.delete_many(query_filter)
		L.log(asab.LOG_NOTICE, "WebAuthn credentials deleted", struct_data={
			"cid": credentials_id,
			"count": result.deleted_count
		})


	async def create_registration_challenge(self, session_id: str) -> bytes:
		"""
		Create and return WebAuthn registration challenge for the current session
		"""
		# Delete existing challenge
		try:
			await self.delete_registration_challenge(session_id)
		except KeyError:
			# There is no challenge associated with this user session
			pass

		upsertor = self.StorageService.upsertor(self.WebAuthnRegistrationChallengeCollection, obj_id=session_id)

		expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(milliseconds=self.RegistrationTimeout)
		upsertor.set("exp", expires)

		challenge = secrets.token_bytes(32)
		upsertor.set("ch", challenge)

		await upsertor.execute(event_type=EventTypes.WEBAUTHN_REG_CHALLENGE_CREATED)
		L.log(asab.LOG_NOTICE, "WebAuthn challenge created", struct_data={"sid": session_id})

		return challenge


	async def get_registration_challenge(self, session_id: str) -> bytes:
		"""
		Get existing WebAuthn registration challenge for the current session
		"""
		challenge_obj = await self.StorageService.get(self.WebAuthnRegistrationChallengeCollection, session_id)
		if challenge_obj["exp"] < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("Challenge timed out")
		return challenge_obj["ch"]

	async def delete_registration_challenge(self, session_id: str):
		"""
		Delete existing WebAuthn registration challenge for the current session
		"""
		await self.StorageService.delete(self.WebAuthnRegistrationChallengeCollection, session_id)
		L.info("WebAuthn challenge deleted", struct_data={
			"sid": session_id
		})


	async def _delete_expired_challenges(self):
		"""
		Delete expired WebAuthn registration challenges
		"""
		collection = self.StorageService.Database[self.WebAuthnRegistrationChallengeCollection]

		query_filter = {"exp": {"$lt": datetime.datetime.now(datetime.timezone.utc)}}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.log(asab.LOG_NOTICE, "Expired WebAuthn challenges deleted.", struct_data={
				"count": result.deleted_count
			})


	async def create_authentication_challenge(self) -> bytes:
		"""
		Create and return WebAuthn authentication challenge
		"""
		return secrets.token_bytes(32)


	async def get_registration_options(self, session):
		"""
		Get WebAuthn registration options

		https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialcreationoptions
		"""
		credentials = await self.CredentialsService.get(session.Credentials.Id)
		# User_name should be a unique human-palatable identifier (typically email, phone)
		user_name = credentials.get("email") or credentials.get("phone")
		if not user_name:
			raise Exception("Credentials have no email address nor phone number.")

		challenge = await self.create_registration_challenge(session.Session.Id)
		options = webauthn.generate_registration_options(
			rp_id=self.RelyingPartyId,
			rp_name=self.RelyingPartyName,
			user_id=session.Credentials.Id,
			user_name=user_name,
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
		"""
		Register a new WebAuthn credential

		https://www.w3.org/TR/webauthn/#sctn-registering-a-new-credential
		"""
		try:
			challenge = await self.get_registration_challenge(session.Session.Id)
		except KeyError:
			raise KeyError("Challenge does not exist or timed out", {"sid": session.Session.Id})

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
			session.Credentials.Id,
			verified_registration,
			name=public_key_credential.get("key_name"),
		)

		try:
			await self.delete_registration_challenge(session.Session.Id)
		except KeyError:
			# Challenge expired in the meantime
			pass

		return {"result": "OK"}


	async def get_authentication_options(self, credentials_id: str, timeout: int = None):
		"""
		Get WebAuthn authentication options

		https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialrequestoptions
		"""
		wa_credentials = await self.list_webauthn_credentials(credentials_id)
		allow_credentials = [
			webauthn.helpers.structs.PublicKeyCredentialDescriptor(
				id=credential["_id"],
				# transports=...,  # Optional
			) for credential in wa_credentials
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
		Authenticate a WebAuthn credential

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

		wa_credential = await self.get_webauthn_credential(
			base64.urlsafe_b64decode(public_key_credential["rawId"] + b"==")
		)
		public_key = wa_credential["pk"]
		sign_count = wa_credential["sc"]

		if credentials_id != wa_credential["cid"]:
			L.error("WebAuthn login failed: Credentials ID does not match", struct_data={
				"cid": credentials_id,
				"wacid": wa_credential["_id"],
			})
			return False

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
			sign_count=verified_authentication.new_sign_count,
			last_login=datetime.datetime.now(datetime.timezone.utc),
		)

		return True


def _normalize_webauthn_credential_response(public_key_credential):
	"""
	Modify the WebAuthn response in-place so that it fits the webauthn library methods
	"""
	# Re-encode id, which has been automatically decoded in the handler
	public_key_credential["id"] = base64.urlsafe_b64encode(
		public_key_credential["id"].encode("ascii")).decode("ascii").rstrip("=")
	public_key_credential["rawId"] = public_key_credential["rawId"].encode("ascii")

	# Decode response data
	response = public_key_credential["response"]
	for field in ["clientDataJSON", "authenticatorData", "signature", "attestationObject"]:
		if field in response:
			response[field] = base64.urlsafe_b64decode(response[field].encode("ascii") + b"==")
