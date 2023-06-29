import datetime
import logging
import secrets
import uuid

import bson

import hashlib
import cryptography.hazmat.primitives.ciphers
import cryptography.hazmat.primitives.ciphers.algorithms
import cryptography.hazmat.primitives.ciphers.modes


import asab
import asab.storage
import pymongo

from .adapter import SessionAdapter, rest_get

from ..events import EventTypes

#

L = logging.getLogger(__name__)

#


class SessionService(asab.Service):

	SessionCollection = "s"

	def __init__(self, app, service_name='seacatauth.SessionService'):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")

		# SessionService does not use the encryption provided by StorageService.
		# It needs to be able to search by encrypted values and thus requires
		# a different way of handling AES CBC init vectors.
		aes_key = asab.Config.get("asab:storage", "aes_key")
		if len(aes_key) == 0:
			aes_key = asab.Config.get("seacatauth:session", "aes_key", fallback="")
			if len(aes_key) > 0:
				raise ValueError(
					"The 'aes_key' config option has been moved from [seacatauth:session] "
					"into [asab:storage] section. Please update your configuration accordingly.")
		if len(aes_key) == 0:
			raise ValueError("""Storage AES key must not be empty.
				Please specify it in the [asab:storage] section of your Seacat Auth configuration file.
				You may use the following randomly generated example:
				```
				[asab:storage]
				aes_key={}
				```
			""".replace("\t", "").format(secrets.token_urlsafe(16)))
		self.AESKey = hashlib.sha256(aes_key.encode("utf-8")).digest()

		# Block size is used for determining the size of CBC initialization vector
		self.AESBlockSize = cryptography.hazmat.primitives.ciphers.algorithms.AES.block_size // 8

		self.Expiration = datetime.timedelta(
			seconds=asab.Config.getseconds("seacatauth:session", "expiration")
		)

		if len(asab.Config.get("seacatauth:session", "anonymous_expiration")) > 0:
			self.AnonymousExpiration = asab.Config.getseconds("seacatauth:session", "anonymous_expiration")
		else:
			self.AnonymousExpiration = asab.Config.getseconds("seacatauth:session", "expiration")

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
		self.SessionGauge = self.MetricsService.create_gauge(
			"sessions", tags={"help": "Counts active sessions."}, init_values={"sessions": 0})
		app.PubSub.subscribe("Application.tick/10!", self._on_tick_metric)


	async def initialize(self, app):
		# Initialize indexes
		collection = await self.StorageService.collection(self.SessionCollection)

		# Access token
		try:
			await collection.create_index(
				[(SessionAdapter.FN.OAuth2.AccessToken, pymongo.ASCENDING)],
				unique=True,
				partialFilterExpression={
					SessionAdapter.FN.OAuth2.AccessToken: {"$exists": True, "$gt": b""}}
			)
		except Exception as e:
			L.error("Failed to create index (access token): {}".format(e))

		# Cookie ID + client ID
		try:
			await collection.create_index(
				[
					(SessionAdapter.FN.Cookie.Id, pymongo.ASCENDING),
					(SessionAdapter.FN.OAuth2.ClientId, pymongo.ASCENDING),
				],
				unique=True,
				partialFilterExpression={
					SessionAdapter.FN.Cookie.Id: {"$exists": True, "$gt": b""}}
			)
		except Exception as e:
			L.error("Failed to create compound index (cookie ID, client ID): {}".format(e))

		# Expiration descending
		# Optimizes deleting expired sessions
		try:
			await collection.create_index(
				[
					(SessionAdapter.FN.Session.Expiration, pymongo.DESCENDING)
				]
			)
		except Exception as e:
			L.error("Failed to create index (expiration descending): {}".format(e))

		# Parent session
		# For searching session groups
		try:
			await collection.create_index(
				[
					(SessionAdapter.FN.Session.ParentSessionId, pymongo.ASCENDING)
				]
			)
		except Exception as e:
			L.error("Failed to create index (parent session ID): {}".format(e))


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
		# TODO: Improve performance - each self.delete(session_id) call searches for potential subsessions!
		expired = []
		async for session in self._iterate_raw(
			query_filter={SessionAdapter.FN.Session.Expiration: {"$lt": datetime.datetime.now(datetime.timezone.utc)}}
		):
			expired.append(session["_id"])

		for sid in expired:
			# Use the delete method for proper session termination
			await self.delete(session_id=sid)


	async def create_session(
		self,
		session_type: str,
		parent_session_id: bson.ObjectId = None,
		expiration: float = None,
		session_builders: list = None
	):
		upsertor = self.StorageService.upsertor(self.SessionCollection)

		# Set up required fields
		if session_type not in frozenset(["root", "openidconnect", "m2m", "cookie"]):
			L.error("Unsupported session type", struct_data={"type": session_type})
			return None
		upsertor.set(SessionAdapter.FN.Session.Type, session_type)
		if parent_session_id is not None:
			upsertor.set(SessionAdapter.FN.Session.ParentSessionId, parent_session_id)

		# Set up expiration variables
		if expiration is not None:
			expiration = datetime.timedelta(seconds=expiration)
			if expiration > self.MaximumAge:
				# TODO: Cut the expiration or raise error
				L.warning("Session expiration exceeds maximum session age.")
		else:
			expiration = self.Expiration
		expires = datetime.datetime.now(datetime.timezone.utc) + expiration
		max_expiration = datetime.datetime.now(datetime.timezone.utc) + self.MaximumAge
		if self.TouchExtensionSeconds is not None:
			touch_extension_seconds = self.TouchExtensionSeconds
		else:
			touch_extension_seconds = self.TouchExtensionRatio * expiration.total_seconds()

		upsertor.set(SessionAdapter.FN.Session.Expiration, expires)
		upsertor.set(SessionAdapter.FN.Session.MaxExpiration, max_expiration)
		upsertor.set(SessionAdapter.FN.Session.ExpirationExtension, touch_extension_seconds)

		# Add builder fields
		if session_builders is None:
			session_builders = list()
		for session_builder in session_builders:
			for key, value in session_builder:
				if key in SessionAdapter.SensitiveFields and value is not None:
					value = SessionAdapter.EncryptedPrefix + self.aes_encrypt(value)
				upsertor.set(key, value)

		session_id = await upsertor.execute(event_type=EventTypes.SESSION_CREATED)

		struct_data = {
			"sid": session_id,
			"type": session_type,
		}
		if parent_session_id is not None:
			struct_data["parent_sid"] = parent_session_id
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

		await upsertor.execute(event_type=EventTypes.SESSION_UPDATED)

		return await self.get(session_id)


	async def get_by(self, criteria: dict):
		# Encrypt sensitive fields
		query_filter = {}
		for key, value in criteria.items():
			if key in SessionAdapter.SensitiveFields:
				query_filter[key] = SessionAdapter.EncryptedPrefix + self.aes_encrypt(value)
			else:
				query_filter[key] = value

		collection = self.StorageService.Database[self.SessionCollection]
		session_dict = await collection.find_one(query_filter)
		if session_dict is None:
			raise KeyError("Session not found")

		try:
			session = SessionAdapter(self, session_dict)
		except Exception as e:
			L.error("Failed to create SessionAdapter from database object", struct_data={
				"sid": session_dict.get("_id"),
			})
			raise KeyError("Session not found") from e

		return session


	async def get(self, session_id):
		if isinstance(session_id, str):
			session_id = bson.ObjectId(session_id)
		session_dict = await self.StorageService.get(self.SessionCollection, session_id)
		try:
			session = SessionAdapter(self, session_dict)
		except Exception as e:
			L.error("Failed to create SessionAdapter from database object", struct_data={
				"sid": session_dict.get("_id"),
			})
			raise e
		return session


	async def _iterate_raw(self, page: int = 0, limit: int = None, query_filter: dict = None):
		"""
		Yields raw session dicts including ALL the fields.
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
			sessions.append(rest_get(session_dict))

		return {
			'data': sessions,
			'count': await collection.count_documents(query_filter)
		}


	async def recursive_list(self, page: int = 0, limit: int = None, query_filter=None):
		"""
		List top-level sessions with all their children sessions inside the "children" attribute
		"""
		collection = self.StorageService.Database[self.SessionCollection]

		if query_filter is None:
			query_filter = {}

		# Find only top-level sessions (with no parent)
		query_filter.update({SessionAdapter.FN.Session.ParentSessionId: None})

		cursor = collection.find(query_filter)

		cursor.sort('_c', -1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		sessions = []
		count = await collection.count_documents(query_filter)
		async for session_dict in self._iterate_raw(page, limit, query_filter):
			try:
				session = SessionAdapter(self, session_dict).rest_get()
			except Exception as e:
				L.error("Failed to create SessionAdapter from database object: {}".format(e), struct_data={
					"sid": session_dict.get("_id"),
				})
				await self.delete(session_dict.get(SessionAdapter.FN.SessionId))
				continue
			# Include children sessions
			children = await self.list(
				query_filter={SessionAdapter.FN.Session.ParentSessionId: bson.ObjectId(session["_id"])}
			)
			if children["count"] > 0:
				session["children"] = children
			sessions.append(session)

		return {
			'data': sessions,
			'count': count
		}


	async def count_sessions(self, query_filter=None):
		collection = self.StorageService.Database[self.SessionCollection]

		if query_filter is None:
			return await collection.estimated_document_count()

		return await collection.count_documents(query_filter)


	async def touch(self, session: SessionAdapter, expiration: int = None):
		"""
		Extend the expiration of the session group if it hasn't been updated recently.

		Return the updated session object.
		"""
		# Extend parent session
		if session.Session.ParentSessionId is not None:
			await self.touch(await self.get(session.Session.ParentSessionId))

		if datetime.datetime.now(datetime.timezone.utc) < session.Session.ModifiedAt + self.MinimalRefreshInterval:
			# Session has been extended recently
			return session
		if session.Session.Expiration >= session.Session.MaxExpiration:
			# Session expiration is already maxed out
			return session

		if expiration is not None:
			expiration = datetime.timedelta(seconds=expiration)
		elif session.Session.ExpirationExtension is not None:
			expiration = datetime.timedelta(seconds=session.Session.ExpirationExtension)
		else:
			# May be a legacy "machine credentials session". Do not extend.
			return session
		expires = datetime.datetime.now(datetime.timezone.utc) + expiration

		if expires < session.Session.Expiration:
			# Do not shorten the session!
			return session
		if expires > session.Session.MaxExpiration:
			# Do not cross maximum expiration
			expires = session.Session.MaxExpiration

		# Update session
		version = session.Session.Version
		upsertor = self.StorageService.upsertor(
			self.SessionCollection,
			session.SessionId,
			version=version
		)
		upsertor.set(SessionAdapter.FN.Session.Expiration, expires)

		try:
			await upsertor.execute(event_type=EventTypes.SESSION_EXTENDED)
			L.log(asab.LOG_NOTICE, "Session expiration extended", struct_data={"sid": session.Session.Id, "exp": expires})
		except KeyError:
			L.warning("Conflict: Session already extended", struct_data={"sid": session.Session.Id})

		return await self.get(session.SessionId)


	async def delete(self, session_id):
		# Recursively delete all child sessions first
		query_filter = {SessionAdapter.FN.Session.ParentSessionId: bson.ObjectId(session_id)}

		to_delete = []
		async for session_dict in self._iterate_raw(query_filter=query_filter):
			to_delete.append(session_dict)

		for session_dict in to_delete:
			await self.delete(session_dict["_id"])

		# Delete the session itself
		await self.StorageService.delete(self.SessionCollection, bson.ObjectId(session_id))
		L.log(asab.LOG_NOTICE, "Session deleted", struct_data={"sid": session_id})

		# TODO: Publish pubsub message for session deletion


	async def delete_all_sessions(self):
		await self._delete_sessions_by_filter()

	async def _delete_sessions_by_filter(self, query_filter=None):
		query_filter = query_filter or {}
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

	async def delete_sessions_by_credentials_id(self, credentials_id):
		await self._delete_sessions_by_filter(
			query_filter={SessionAdapter.FN.Credentials.Id: credentials_id})


	async def delete_sessions_by_tenant_in_scope(self, tenant):
		await self._delete_sessions_by_filter(
			query_filter={"{}.{}".format(SessionAdapter.FN.Authorization.Authz, tenant): {"$exists": True}})


	async def inherit_track_id_from_root(self, session: SessionAdapter) -> SessionAdapter:
		"""
		Fetch the session's parent and check for track ID. If there is any, copy it to the session.
		"""
		# Get root session if it exists
		if session.Session.ParentSessionId is not None:
			root_session = await self.get(session.Session.ParentSessionId)
			if root_session.TrackId is not None:
				# This can happen if there are multiple authorize calls from the same subject
				L.warning("Root session changed between authorize and token request.", struct_data={
					"client_session": session.SessionId,
					"root_session": root_session.SessionId,
				})
				# Transfer the new track ID from the root session to the new session
				sub_session_builders = [
					((SessionAdapter.FN.Session.TrackId, uuid.uuid4().bytes),),
				]
				await self.update_session(
					session.SessionId,
					session_builders=sub_session_builders)
				session = await self.get(session.SessionId)
		return session


	async def inherit_or_generate_new_track_id(
		self, dst_session: SessionAdapter, src_session: SessionAdapter
	) -> SessionAdapter:
		"""
		Check if the request has a session identifier (access token or cookie, in this order)
		and try to inherit the track id.
		If needed, create a root session for these two sessions.
		"""
		if src_session is None:
			# No source session
			# Update the destination session with a new track ID
			# Also update its root session if there is any
			root_session_id = dst_session.Session.ParentSessionId
			session_builders = [((SessionAdapter.FN.Session.TrackId, uuid.uuid4().bytes),)]
			await self.update_session(dst_session.SessionId, session_builders)
			if root_session_id is not None:
				await self.update_session(root_session_id, session_builders)

		elif not src_session.Authentication.IsAnonymous:
			L.info("Cannot transfer Track ID: Source session is not anonymous.", struct_data={
				"src_sid": src_session.SessionId, "dst_sid": dst_session.SessionId})
			root_session_id = dst_session.Session.ParentSessionId
			session_builders = [((SessionAdapter.FN.Session.TrackId, uuid.uuid4().bytes),)]
			await self.update_session(dst_session.SessionId, session_builders)
			if root_session_id is not None:
				await self.update_session(root_session_id, session_builders)

		elif src_session.OAuth2.ClientId != dst_session.OAuth2.ClientId:
			L.info("Cannot transfer Track ID: Mismatching client IDs.", struct_data={
				"src_clid": src_session.OAuth2.ClientId, "dst_clid": dst_session.OAuth2.ClientId})
			root_session_id = dst_session.Session.ParentSessionId
			session_builders = [((SessionAdapter.FN.Session.TrackId, uuid.uuid4().bytes),)]
			await self.update_session(dst_session.SessionId, session_builders)
			if root_session_id is not None:
				await self.update_session(root_session_id, session_builders)

		elif src_session.TrackId is None:
			L.info("Cannot transfer Track ID: Source session has no Track ID.", struct_data={
				"src_sid": src_session.SessionId, "dst_sid": dst_session.SessionId})
			root_session_id = dst_session.Session.ParentSessionId
			session_builders = [((SessionAdapter.FN.Session.TrackId, uuid.uuid4().bytes),)]
			await self.update_session(dst_session.SessionId, session_builders)
			if root_session_id is not None:
				await self.update_session(root_session_id, session_builders)

		elif not dst_session.Authentication.IsAnonymous:
			# The destination session is authenticated while the source one is anonymous
			# Transfer the track ID to the destination session and delete the source session
			assert dst_session.Session.ParentSessionId is not None
			session_builders = [((SessionAdapter.FN.Session.TrackId, src_session.Session.TrackId),)]
			old_session_group_id = src_session.Session.ParentSessionId or src_session.SessionId
			await self.delete(old_session_group_id)
			await self.update_session(dst_session.SessionId, session_builders)
			await self.update_session(dst_session.Session.ParentSessionId, session_builders)

		elif src_session.Session.Type != dst_session.Session.Type:
			# The source and the destination sessions are both anonymous but of a different type (cookie vs token)
			# Group them together under the same root session
			root_session_id = dst_session.Session.ParentSessionId or src_session.Session.ParentSessionId
			root_session_builders = [
				((SessionAdapter.FN.Session.TrackId, src_session.Session.TrackId),),
			]
			if root_session_id is not None:
				# Update the root session
				root_session = await self.get(root_session_id)
				assert root_session.Session.TrackId is None
				await self.update_session(root_session_id, session_builders=root_session_builders)
			else:
				# Create a new root session
				root_session_builders.extend([
					((SessionAdapter.FN.Credentials.Id, dst_session.Credentials.Id),),
					((SessionAdapter.FN.Authentication.IsAnonymous, True),),
				])
				await self.create_session(
					"root", session_builders=root_session_builders, expiration=self.AnonymousExpiration)
			sub_session_builders = [
				((SessionAdapter.FN.Session.ParentSessionId, root_session_id),),
				((SessionAdapter.FN.Session.TrackId, src_session.Session.TrackId),),
			]
			await self.update_session(dst_session.SessionId, session_builders=sub_session_builders)
			await self.update_session(src_session.SessionId, session_builders=sub_session_builders)

		else:
			# The source and the destination sessions are both anonymous and of the same type (cookie or token)
			# There shouldn't be more than one anonymous session per credentials per client per type
			# Transfer the track ID and delete the source session
			assert dst_session.Session.ParentSessionId is None
			session_builders = [((SessionAdapter.FN.Session.TrackId, src_session.Session.TrackId),)]
			old_session_group_id = src_session.Session.ParentSessionId or src_session.SessionId
			await self.delete(old_session_group_id)
			await self.update_session(dst_session.SessionId, session_builders)

		return await self.get(dst_session.SessionId)


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
