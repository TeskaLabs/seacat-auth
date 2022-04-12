import json
import secrets
import datetime
import typing

import cryptography.hazmat.backends
import cryptography.hazmat.primitives.asymmetric.ec


class LoginSession(object):


	ServerLoginKeyCurve = cryptography.hazmat.primitives.asymmetric.ec.SECP256R1


	def __init__(self, client_login_key, credentials_id, login_descriptors, login_attempts, login_expiration):
		self.CreatedAt = datetime.datetime.utcnow()
		self.ServerLoginKey = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
			self.ServerLoginKeyCurve(),
			cryptography.hazmat.backends.default_backend()
		)
		self.Id = secrets.token_urlsafe()

		if client_login_key is not None:
			self.ClientLoginKey = client_login_key  # Public key
			self.__shared_key = self.ServerLoginKey.exchange(
				cryptography.hazmat.primitives.asymmetric.ec.ECDH(),
				self.ClientLoginKey
			)
		else:
			# Dummy login session, only used after successful external login
			self.ClientLoginKey = None
			self.__shared_key = None

		self.CredentialsId = credentials_id
		self.LoginDescriptors = login_descriptors
		self.RemainingLoginAttempts = login_attempts
		self.ExpiresAt = datetime.datetime.utcnow() + datetime.timedelta(seconds=login_expiration)

		# Login descriptor that successfully authenticated the login session
		self.AuthenticatedVia = None

		# User space for storing custom data needed by a login process
		self.Data = {}


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
