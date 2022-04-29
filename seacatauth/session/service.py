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
			raise ValueError("""Session AES key must not be empty.
				Please specify it in the [seacatauth:session] section of your Seacat Auth configuration file.
				You may use the following randomly generated example:
				```
				[seacatauth:session]
				aes_key={}
				```
			""".replace("\t", "").format(secrets.token_urlsafe(16)))
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

		# Metrics
		self.MetricsService = app.get_service('asab.MetricsService')
		self.TaskService = app.get_service('asab.TaskService')
		self.SessionGauge = self.MetricsService.create_gauge("sessions", tags={"help": "Counts active sessions."}, init_values={"sessions": 0})
		app.PubSub.subscribe("Application.tick/10!", self._on_tick_metric)


	async def _on_start(self, event_name):
		await self.delete_expired_sessions()


	async def _on_tick(self, event_name):
		await self.delete_expired_sessions()

	def _on_tick_metric(self, event_name):
		self.TaskService.schedule(self._metrics_task())

	async def _metrics_task(self):
		session_count = await self.count_sessions()
		self.SessionGauge.set("sessions", session_count)


	async def delete_expired_sessions(self):
		expired = []
		async for session in self._iterate_raw(
			query_filter={SessionAdapter.FNExpiration: {"$lt": datetime.datetime.utcnow()}}
		):
			expired.append(session["_id"])

		for sid in expired:
			# Use the delete method for proper session termination
			await self.delete(session_id=sid)


	async def create_session(
		self,
		session_type: str,
		parent_session: SessionAdapter = None,
		expiration: float = None,
		session_builders: list = None
	):
		upsertor = self.StorageService.upsertor(self.SessionCollection)

		# Set up required fields
		if session_type not in frozenset(["root", "openidconnect", "m2m", "cookie"]):
			L.error("Unsupported session type", struct_data={"type": session_type})
			return None
		upsertor.set(SessionAdapter.FNSessionType, session_type)
		if parent_session is not None:
			upsertor.set(SessionAdapter.FNParentSessionId, parent_session.SessionId)

		# Set up expiration variables
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

		upsertor.set(SessionAdapter.FNExpiration, expires)
		upsertor.set(SessionAdapter.FNMaxExpiration, max_expiration)
		upsertor.set(SessionAdapter.FNTouchExtension, touch_extension_seconds)

		# Add builder fields
		if session_builders is None:
			session_builders = list()
		for session_builder in session_builders:
			for key, value in session_builder:
				if key in SessionAdapter.SensitiveFields:
					value = SessionAdapter.EncryptedPrefix + self.aes_encrypt(value)
				upsertor.set(key, value)

		session_id = await upsertor.execute()

		struct_data = {
			"sid": session_id,
			"type": session_type,
		}
		if parent_session is not None:
			struct_data["parent_sid"] = parent_session.SessionId
		L.log(asab.LOG_NOTICE, "Session created", struct_data=struct_data)
		return await self.get(session_id)


	async def update_session(self, session_id: str, session_builders: list):
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


	async def _iterate_raw(self, page: int = 0, limit: int = None, query_filter=None):
		"""
		Yields raw session dicts
		"""
		collection = self.StorageService.Database[self.SessionCollection]

		if query_filter is None:
			query_filter = {}
		cursor = collection.find(query_filter)

		cursor.sort('_c', -1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		async for session_dict in cursor:
			yield session_dict


	async def list(self, page: int = 0, limit: int = None, query_filter=None):
		collection = self.StorageService.Database[self.SessionCollection]

		if query_filter is None:
			query_filter = {}

		sessions = []
		async for session_dict in self._iterate_raw(page, limit, query_filter):
			sessions.append(SessionAdapter(self, session_dict))

		return {
			'data': sessions,
			'count': await collection.count_documents(query_filter)
		}


	async def structured_list(self, page: int = 0, limit: int = None, query_filter=None):
		"""
		List top-level sessions with all their children sessions inside the "children" attribute
		"""
		collection = self.StorageService.Database[self.SessionCollection]

		if query_filter is None:
			query_filter = {}

		# Find only top-level sessions (with no parent)
		query_filter.update({SessionAdapter.FNParentSessionId: None})

		cursor = collection.find(query_filter)

		cursor.sort('_c', -1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		sessions = []
		count = await collection.count_documents(query_filter)
		async for session_dict in self._iterate_raw(page, limit, query_filter):
			session = SessionAdapter(self, session_dict).rest_get()
			# Include children sessions
			session["children"] = await self.list(query_filter={SessionAdapter.FNParentSessionId: session["_id"]})
			sessions.append(session)

		return {
			'data': sessions,
			'count': count
		}


	async def count_sessions(self, query_filter=None):
		collection = self.StorageService.Database[self.SessionCollection]

		if query_filter is None:
			query_filter = {}

		return await collection.count_documents(query_filter)


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
		upsertor.set(SessionAdapter.FNExpiration, expires)

		try:
			await upsertor.execute()
			L.log(asab.LOG_NOTICE, "Session expiration extended", struct_data={"sid": session.SessionId, "exp": expires})
		except KeyError:
			L.warning("Conflict: Session already extended", struct_data={"sid": session.SessionId})


	async def delete(self, session_id):
		# Recursively delete all child sessions first
		query_filter = {SessionAdapter.FNParentSessionId: session_id}

		to_delete = []
		async for session_dict in self._iterate_raw(query_filter=query_filter):
			to_delete.append(session_dict)

		for session_dict in to_delete:
			await self.delete(session_dict["_id"])

		# Delete the session itself
		await self.StorageService.delete(self.SessionCollection, session_id)
		L.log(asab.LOG_NOTICE, "Session deleted", struct_data={"sid": session_id})

		# TODO: Publish pubsub message for session deletion


	async def delete_all_sessions(self):
		to_delete = []
		async for session_dict in self._iterate_raw():
			to_delete.append(session_dict)

		deleted = 0
		failed = 0
		# Delete iteratively so that every session is terminated properly
		for session_dict in to_delete:
			try:
				# TODO: Publish pubsub message for session deletion
				await self.StorageService.delete(self.SessionCollection, session_dict["_id"])
				deleted += 1
			except Exception as e:
				L.error("Cannot delete session", struct_data={
					"sid": session_dict["_id"],
					"error": type(e).__name__
				})
				failed += 1

		L.log(asab.LOG_NOTICE, "Sessions deleted", struct_data={
			"deleted_count": deleted,
			"failed_count": failed
		})

	async def delete_sessions_by_credentials_id(self, credentials_id):
		query_filter = {SessionAdapter.FNCredentialsId: credentials_id}
		to_delete = []
		async for session_dict in self._iterate_raw(query_filter=query_filter):
			to_delete.append(session_dict)

		deleted = 0
		failed = 0
		# Delete iteratively so that every session is terminated properly
		for session_dict in to_delete:
			try:
				# TODO: Publish pubsub message for session deletion
				await self.StorageService.delete(self.SessionCollection, session_dict["_id"])
				deleted += 1
			except Exception as e:
				L.error("Cannot delete session", struct_data={
					"sid": session_dict["_id"],
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
