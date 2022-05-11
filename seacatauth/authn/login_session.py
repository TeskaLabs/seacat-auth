import json
import secrets
import datetime
import typing

import cryptography.hazmat.backends
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.serialization

from .login_descriptor import LoginDescriptor


class LoginSession(object):

	ServerLoginKeyCurve = cryptography.hazmat.primitives.asymmetric.ec.SECP256R1

	def __init__(
		self,
		id,
		shared_key,
		credentials_id,
		login_descriptors,
		remaining_login_attempts,
		expires_at,
		public_key=None,
		data=None
	):
		self.Id = id
		self.__shared_key = shared_key
		self.CredentialsId = credentials_id
		self.LoginDescriptors = login_descriptors
		self.RemainingLoginAttempts = remaining_login_attempts
		self.ExpiresAt = expires_at
		self.PublicKey = public_key

		# User space for storing custom data needed by a login process
		self.Data = data or {}

		# Login descriptor that successfully authenticated the login session
		self.AuthenticatedVia = None


	@classmethod
	def build(cls, client_login_key, credentials_id, login_descriptors, login_attempts, timeout):
		# Generate shared encryption key
		server_login_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
			cls.ServerLoginKeyCurve(),
			cryptography.hazmat.backends.default_backend()
		)
		shared_key = server_login_key.exchange(
			cryptography.hazmat.primitives.asymmetric.ec.ECDH(),
			client_login_key
		)

		expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=timeout)

		return cls(
			id=secrets.token_urlsafe(),
			shared_key=shared_key,
			credentials_id=credentials_id,
			login_descriptors=login_descriptors,
			remaining_login_attempts=login_attempts,
			expires_at=expires_at,
			public_key=server_login_key.public_key(),
		)


	def serialize(self) -> dict:
		db_object = {
			"_id": self.Id,
			"__sk": self.__shared_key,  # TODO: Revise this. Storing plaintext shared key is not secure.
			"pk": self.PublicKey.public_bytes(
				encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
				format=cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo
			),
			"cid": self.CredentialsId,
			"exp": self.ExpiresAt,
			"la": self.RemainingLoginAttempts,
			"ld": [
				descriptor.serialize()
				for descriptor in self.LoginDescriptors
			],
			"d": self.Data,
		}
		return db_object


	@classmethod
	def deserialize(cls, authn_svc, db_object: dict):
		return cls(
			id=db_object["_id"],
			shared_key=db_object["__sk"],
			credentials_id=db_object["cid"],
			login_descriptors=[
				LoginDescriptor.deserialize(authn_svc, descriptor)
				for descriptor in db_object["ld"]
			],
			remaining_login_attempts=db_object["la"],
			expires_at=db_object["exp"],
			public_key=cryptography.hazmat.primitives.serialization.load_pem_public_key(db_object["pk"]),
			data=db_object["d"],
		)


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
