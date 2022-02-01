import datetime
import logging
import secrets

import bson

import hashlib
import cryptography.hazmat.primitives.ciphers
import cryptography.hazmat.primitives.ciphers.algorithms
import cryptography.hazmat.primitives.ciphers.modes


import asab
import asab.storage

from .adapter import SessionAdapter

#

L = logging.getLogger(__name__)

#


class SessionService(asab.Service):

	SessionCollection = "s"

	def __init__(self, app, service_name='seacatauth.SessionService'):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")

		aes_key = asab.Config.get("seacatauth:session", "aes_key")
		if len(aes_key) == 0:
			raise ValueError("""
				Session AES key must not be empty. 
				Please specify it in the [seacatauth:session] section of your Seacat Auth configuration file.
				You may use the following randomly generated example:
				
				[seacatauth:session]
				aes_key={}
			""".replace("\t", "").format(secrets.token_urlsafe(24)))
		self.AESKey = hashlib.sha256(aes_key.encode("utf-8")).digest()
		# Block size is used for determining the size of CBC initialization vector
		self.AESBlockSize = cryptography.hazmat.primitives.ciphers.algorithms.AES.block_size // 8

		self.Expiration = datetime.timedelta(
			seconds=asab.Config.getseconds("seacatauth:session", "expiration")
		)

		touch_extension = asab.Config.get("seacatauth:session", "touch_extension")
		# Touch extension can be either
		#   specified as a ratio of the original expiration (float between 0 and 1)
		#   specified as absolute duration (float followed by a unit, e.g. "40m", "5h", "30d")
		if touch_extension[-1] in frozenset("0123456789."):
			self.TouchExtensionRatio = float(touch_extension)
			self.TouchExtensionSeconds = None
			if not (0 <= self.TouchExtensionRatio <= 1):
				raise ValueError("Session extension_ratio must be a float between 0 and 1.")
		else:
			self.TouchExtensionSeconds = asab.Config.getseconds("seacatauth:session", "touch_extension")
			self.TouchExtensionRatio = None

		self.MaximumAge = datetime.timedelta(
			seconds=asab.Config.getseconds("seacatauth:session", "maximum_age")
		)

		self.MinimalRefreshInterval = datetime.timedelta(seconds=60)

		app.PubSub.subscribe("Application.tick/60!", self._on_tick)
		app.PubSub.subscribe("Application.run!", self._on_start)


	async def _on_start(self, event_name):
		await self.delete_expired_sessions()


	async def _on_tick(self, event_name):
		await self.delete_expired_sessions()


	async def delete_expired_sessions(self):
		expired = []
		sessions = await self.list()
		for s in sessions["data"]:
			try:
				if datetime.datetime.utcnow() > s["exp"]:
					expired.append(s["_id"])
			except KeyError:
				L.info("Session '{}' is missing exp.".format(s["_id"]))
				continue

		for sid in expired:
			await self.delete(session_id=sid)


	async def create_session(self, session_builders=None, *, expiration: float = None):
		upsertor = self.StorageService.upsertor(self.SessionCollection)
		if session_builders is None:
			session_builders = list()
		for session_builder in session_builders:
			for key, value in session_builder:
				if key in SessionAdapter.SensitiveFields:
					value = SessionAdapter.EncryptedPrefix + self.aes_encrypt(value)
				upsertor.set(key, value)

		if expiration is not None:
			expiration = datetime.timedelta(seconds=expiration)
			if expiration > self.MaximumAge:
				# TODO: Cut the expiration or raise error
				L.warning("Session expiration exceeds maximum session age.")
		else:
			expiration = self.Expiration
		expires = datetime.datetime.utcnow() + expiration
		max_expiration = datetime.datetime.utcnow() + self.MaximumAge
		if self.TouchExtensionSeconds is not None:
			touch_extension_seconds = self.TouchExtensionSeconds
		else:
			touch_extension_seconds = self.TouchExtensionRatio * expiration.total_seconds()

		upsertor.set("exp", expires)
		upsertor.set("max_exp", max_expiration)
		upsertor.set("touch_ext", touch_extension_seconds)

		session_id = await upsertor.execute()

		L.log(asab.LOG_NOTICE, "Session created", struct_data={
			'sid': session_id,
			'exp': expires
		})
		return await self.get(session_id)


	async def update_session(self, session_id, session_builders=[]):
		if isinstance(session_id, str):
			session_id = bson.ObjectId(session_id)
		session_dict = await self.StorageService.get(self.SessionCollection, session_id)

		upsertor = self.StorageService.upsertor(
			self.SessionCollection,
			obj_id=session_id,
			version=session_dict['_v'],
		)

		for session_builder in session_builders:
			for key, value in session_builder:
				upsertor.set(key, value)

		await upsertor.execute()

		return await self.get(session_id)


	async def get_by(self, key, value):
		# Encrypt sensitive fields
		# BACK COMPAT: Do not encrypt old tokens (36 bytes long)
		# TODO: Remove support once proper m2m tokens are in place
		is_old_token = False
		if key in SessionAdapter.SensitiveFields:
			if len(value) < 48:
				is_old_token = True
			else:
				value = SessionAdapter.EncryptedPrefix + self.aes_encrypt(value)
		session_dict = await self.StorageService.get_by(self.SessionCollection, key=key, value=value)
		session = SessionAdapter(self, session_dict)

		if is_old_token:
			L.warning("Access with obsolete access token.", struct_data={
				"at": value,
				"sid": session.SessionId,
				"cid": session.CredentialsId
			})

		return session


	async def get(self, session_id):
		if isinstance(session_id, str):
			session_id = bson.ObjectId(session_id)
		session_dict = await self.StorageService.get(self.SessionCollection, session_id)
		session = SessionAdapter(self, session_dict)
		return session


	async def list(self, page: int = 0, limit: int = None, query_filter=None):
		collection = self.StorageService.Database[self.SessionCollection]

		if query_filter is None:
			query_filter = {}
		cursor = collection.find(query_filter)

		cursor.sort('_c', -1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		sessions = []
		async for session_dict in cursor:
			sessions.append(session_dict)

		return {
			'data': sessions,
			'count': await collection.count_documents(query_filter)
		}


	async def touch(self, session: SessionAdapter, expiration: int = None):
		"""
		Extend the expiration of the session if it hasn't been updated recently.
		"""
		if datetime.datetime.utcnow() < session.ModifiedAt + self.MinimalRefreshInterval:
			# Session has been extended recently
			return
		if session.Expiration == session.MaxExpiration:
			# Session expiration is already maxed out
			return

		if expiration is not None:
			expiration = datetime.timedelta(seconds=expiration)
		elif session.TouchExtension is not None:
			expiration = datetime.timedelta(seconds=session.TouchExtension)
		else:
			# May be a legacy "machine credentials session". Do not extend.
			return
		expires = datetime.datetime.utcnow() + expiration

		if expires < session.Expiration:
			# Do not shorten the session!
			return
		if expires > session.MaxExpiration:
			# Do not cross maximum expiration
			expires = session.MaxExpiration

		# Update session
		version = session.Version
		upsertor = self.StorageService.upsertor(
			self.SessionCollection,
			session.SessionId,
			version=version
		)
		upsertor.set("exp", expires)

		try:
			await upsertor.execute()
			L.log(asab.LOG_NOTICE, "Session expiration extended", struct_data={"sid": session.SessionId, "exp": expires})
		except KeyError:
			L.warning("Conflict: Session already extended", struct_data={"sid": session.SessionId})


	async def delete(self, session_id):
		await self.StorageService.delete(self.SessionCollection, bson.ObjectId(session_id))
		L.log(asab.LOG_NOTICE, "Session deleted", struct_data={'sid': session_id})

		# TODO: Publish pubsub message for session deletion


	async def delete_all_sessions(self):
		sessions = (await self.list())["data"]

		deleted = 0
		failed = 0
		# Delete iteratively so that every session is terminated properly
		for session in sessions:
			try:
				await self.delete(session["_id"])
				deleted += 1
			except Exception as e:
				L.error("Cannot delete session", struct_data={
					"sid": session["_id"],
					"error": type(e).__name__
				})
				failed += 1

		L.log(asab.LOG_NOTICE, "Sessions deleted", struct_data={
			"deleted_count": deleted,
			"failed_count": failed
		})

	async def delete_sessions_by_credentials_id(self, credentials_id):
		query_filter = {SessionAdapter.FNCredentialsId: credentials_id}
		sessions = (await self.list(query_filter=query_filter))["data"]

		deleted = 0
		failed = 0
		# Delete iteratively so that every session is terminated properly
		for session in sessions:
			try:
				await self.delete(session["_id"])
				deleted += 1
			except Exception as e:
				L.error("Cannot delete session", struct_data={
					"sid": session["_id"],
					"error": type(e).__name__
				})
				failed += 1

		L.log(asab.LOG_NOTICE, "Sessions deleted", struct_data={
			"deleted_count": deleted,
			"failed_count": failed
		})

	def aes_encrypt(self, raw_bytes: bytes):
		algorithm = cryptography.hazmat.primitives.ciphers.algorithms.AES(self.AESKey)
		iv, token = raw_bytes[:self.AESBlockSize], raw_bytes[self.AESBlockSize:]
		mode = cryptography.hazmat.primitives.ciphers.modes.CBC(iv)
		cipher = cryptography.hazmat.primitives.ciphers.Cipher(algorithm, mode)
		encryptor = cipher.encryptor()
		encrypted = iv + (encryptor.update(token) + encryptor.finalize())
		return encrypted

	def aes_decrypt(self, encrypted_bytes: bytes):
		algorithm = cryptography.hazmat.primitives.ciphers.algorithms.AES(self.AESKey)
		iv, token = encrypted_bytes[:self.AESBlockSize], encrypted_bytes[self.AESBlockSize:]
		mode = cryptography.hazmat.primitives.ciphers.modes.CBC(iv)
		cipher = cryptography.hazmat.primitives.ciphers.Cipher(algorithm, mode)
		decryptor = cipher.decryptor()
		raw = iv + (decryptor.update(token) + decryptor.finalize())
		return raw
