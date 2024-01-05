import datetime
import json
import secrets
import typing

import cryptography.hazmat.backends
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.ciphers
import cryptography.hazmat.primitives.ciphers.algorithms
import cryptography.hazmat.primitives.ciphers.modes

from .login_descriptor import LoginDescriptor


class SeacatLogin:

	ServerLoginKeyCurve = cryptography.hazmat.primitives.asymmetric.ec.SECP256R1

	def __init__(
		self,
		ident: str,
		credentials_id: str | None,
		login_descriptors: list | None,
		login_attempts_left: int,
		shared_key: bytes,
		server_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
		data: dict | None = None
	):
		self.Ident = ident
		self.CredentialsId = credentials_id
		self.LoginDescriptors = login_descriptors
		self.LoginAttemptsLeft = login_attempts_left
		self.__shared_key = shared_key
		self.ServerPublicKey = server_public_key

		# Custom data needed by the login process
		self.Data = data or {}


	def __repr__(self):
		return "<SeacatLogin cid={!r} ident={!r}>".format(
			self.CredentialsId, self.Ident)


	@classmethod
	def build(
		cls,
		ident: str,
		credentials_id: str | None,
		login_descriptors: list | None,
		login_attempts_left: int,
		client_login_key
	):
		server_login_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
			cls.ServerLoginKeyCurve(),
			cryptography.hazmat.backends.default_backend()
		)
		if client_login_key is not None:
			shared_key = server_login_key.exchange(
				cryptography.hazmat.primitives.asymmetric.ec.ECDH(),
				client_login_key
			)
		else:
			shared_key = None
		return cls(
			shared_key=shared_key,
			credentials_id=credentials_id,
			ident=ident,
			login_descriptors=login_descriptors,
			login_attempts_left=login_attempts_left,
			server_public_key=server_login_key.public_key(),
		)


	def serialize(self) -> dict:
		return {
			"__sk": self.__shared_key,
			"pk": self.ServerPublicKey.public_bytes(
				encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
				format=cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo
			),
			"cid": self.CredentialsId,
			"la": self.LoginAttemptsLeft,
			"ld": [
				descriptor.serialize()
				for descriptor in self.LoginDescriptors
			],
			"idt": self.Ident,
			"d": self.Data,
		}


	@classmethod
	def deserialize(cls, authn_svc, db_object: dict):
		try:
			return cls(
				shared_key=db_object["__sk"],
				credentials_id=db_object["cid"],
				ident=db_object["idt"],
				login_descriptors=[
					LoginDescriptor.deserialize(authn_svc, descriptor)
					for descriptor in db_object["ld"]
				],
				login_attempts_left=db_object["la"],
				server_public_key=cryptography.hazmat.primitives.serialization.load_pem_public_key(db_object["pk"]),
				data=db_object["d"],
			)
		except KeyError:
			return None


	def decrypt(self, ciphertext: bytes) -> dict:
		assert self.__shared_key is not None
		iv = ciphertext[:12]
		message = ciphertext[12:-16]
		tag = ciphertext[-16:]

		# Construct a Cipher object, with the key, iv, and additionally the
		# GCM tag used for authenticating the message.
		decryptor = cryptography.hazmat.primitives.ciphers.Cipher(
			cryptography.hazmat.primitives.ciphers.algorithms.AES(self.__shared_key),
			cryptography.hazmat.primitives.ciphers.modes.GCM(iv, tag),
			backend=cryptography.hazmat.backends.default_backend()
		).decryptor()

		return json.loads(decryptor.update(message) + decryptor.finalize())


	def encrypt(self, plaintext: typing.Union[str, dict, bytes]) -> bytes:
		assert self.__shared_key is not None
		if isinstance(plaintext, dict):
			plaintext = json.dumps(plaintext).encode('utf-8')
		elif isinstance(plaintext, str):
			plaintext = plaintext.encode('utf-8')

		iv = secrets.token_bytes(12)

		# Construct a Cipher object, with the key, iv, and additionally the
		# GCM tag used for authenticating the message.
		encryptor = cryptography.hazmat.primitives.ciphers.Cipher(
			cryptography.hazmat.primitives.ciphers.algorithms.AES(self.__shared_key),
			cryptography.hazmat.primitives.ciphers.modes.GCM(iv),
			backend=cryptography.hazmat.backends.default_backend()
		).encryptor()

		ciphertext = iv + encryptor.update(plaintext) + encryptor.finalize() + encryptor.tag
		return ciphertext


class ExternalLogin:
	def __init__(
		self,
		provider_type: str,
		nonce: str,
	):
		self.ProviderType = provider_type
		self.Nonce = nonce

	def __repr__(self):
		return "<ExternalLogin provider_type={!r}>".format(
			self.ProviderType)

	def serialize(self) -> dict:
		return {
			"ep": self.ProviderType,
			"en": self.Nonce,
		}

	@classmethod
	def deserialize(cls, db_object: dict):
		try:
			return cls(
				provider_type=db_object["ep"],
				nonce=db_object["en"],
			)
		except KeyError:
			return None


class LoginSession(object):

	EncryptedFields = {"__sk"}

	def __init__(
		self,
		id: str | None = None,
		version: int | None = None,
		created: datetime.datetime | None = None,
		modified: datetime.datetime | None = None,
		initiator_cid: str | None = None,
		initiator_sid: str | None = None,
		authorization_params: dict | None = None,
		seacat_login: SeacatLogin | None = None,
		external_login: ExternalLogin | None = None,
	):
		if id is None:
			self.Id = secrets.token_urlsafe()
		else:
			self.Id = id
		self.Version = version
		self.Created = created
		self.Modified = modified
		self.InitiatorCredentialsId = initiator_cid
		self.InitiatorSessionId = initiator_sid
		self.AuthorizationParams = authorization_params
		self.SeacatLogin = seacat_login
		self.ExternalLogin = external_login


	def __repr__(self):
		return "<LoginSession {!r} seacat_login={!r} external_login={!r}>".format(
			self.Id, self.SeacatLogin, self.ExternalLogin)


	def serialize(self) -> dict:
		db_object = {}
		if self.InitiatorCredentialsId:
			db_object["icid"] = self.InitiatorCredentialsId
		if self.InitiatorSessionId:
			db_object["isid"] = self.InitiatorSessionId
		if self.AuthorizationParams:
			db_object["ap"] = self.AuthorizationParams
		if self.SeacatLogin:
			db_object.update(self.SeacatLogin.serialize())
		if self.ExternalLogin:
			db_object.update(self.ExternalLogin.serialize())
		return db_object


	@classmethod
	def deserialize(cls, authn_svc, db_object: dict):
		return cls(
			id=db_object["_id"],
			version=db_object["_v"],
			created=db_object["_c"],
			modified=db_object["_m"],
			initiator_cid=db_object.get("icid"),
			initiator_sid=db_object.get("isid"),
			authorization_params=db_object.get("ap"),
			seacat_login=SeacatLogin.deserialize(authn_svc, db_object),
			external_login=ExternalLogin.deserialize(db_object),
		)


	def initialize_seacat_login(
		self,
		ident: str,
		credentials_id: str | None,
		login_descriptors: list | None,
		login_attempts_left: int,
		client_login_key
	):
		self.SeacatLogin = SeacatLogin.build(
			ident=ident,
			credentials_id=credentials_id,
			login_descriptors=login_descriptors,
			login_attempts_left=login_attempts_left,
			client_login_key=client_login_key
		)


	def decrypt(self, ciphertext: bytes) -> dict:
		assert self.SeacatLogin is not None
		return self.SeacatLogin.decrypt(ciphertext)


	def encrypt(self, plaintext: typing.Union[str, dict, bytes]) -> bytes:
		assert self.SeacatLogin is not None
		return self.SeacatLogin.encrypt(plaintext)
