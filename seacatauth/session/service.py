import base64
import datetime
import logging
import typing
import uuid
import bson

import hashlib
import cryptography.hazmat.primitives.ciphers
import cryptography.hazmat.primitives.ciphers.algorithms
import cryptography.hazmat.primitives.ciphers.modes
import asab
import asab.storage
import pymongo

from ..models.const import ResourceId
from .. import exceptions
from ..events import EventTypes
from ..models import Session
from ..models.session import rest_get
from .algorithmic import AlgorithmicSessionProvider
from .token import SessionTokenService
from .builders import (
	oauth2_session_builder,
	credentials_session_builder,
	authz_session_builder,
	authentication_session_builder,
	available_factors_session_builder,
	external_login_session_builder,
	cookie_session_builder
)


L = logging.getLogger(__name__)


class SessionService(asab.Service):
	SessionCollection = "s"

	def __init__(self, app, service_name="seacatauth.SessionService"):
		super().__init__(app, service_name)
		self.TokenService = SessionTokenService(app, "seacatauth.SessionTokenService")
		self.StorageService = app.get_service("asab.StorageService")
		self.Algorithmic = AlgorithmicSessionProvider(app)

		# SessionService does not use the encryption provided by StorageService.
		# It needs to be able to search by encrypted values and thus requires
		# a different way of handling AES CBC init vectors.
		aes_key = asab.Config.get("asab:storage", "aes_key")
		self.AESKey = hashlib.sha256(aes_key.encode("utf-8")).digest()
		if "aes_key" in asab.Config["seacatauth:session"]:
			L.warning(
				"The 'aes_key' config option has been moved into [asab:storage] section. "
				"The key specified in [seacatauth:session] will be ignored.")

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
		if self.MaximumAge < self.Expiration:
			raise ValueError("Session maximum_age must be greater than its default expiration.")

		touch_cooldown = asab.Config.getseconds("seacatauth:session", "touch_cooldown")
		self.TouchCooldown = datetime.timedelta(seconds=touch_cooldown)

		app.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)

		# Metrics
		self.MetricsService = app.get_service("asab.MetricsService")
		self.TaskService = app.get_service("asab.TaskService")
		self.SessionGauge = self.MetricsService.create_gauge(
			"sessions", tags={"help": "Counts active sessions."}, init_values={"sessions": 0})
		app.PubSub.subscribe("Application.tick/10!", self._on_tick_metric)


	async def initialize(self, app):
		await self.Algorithmic.initialize(app)

		# Initialize indexes
		collection = await self.StorageService.collection(self.SessionCollection)

		# Access token
		try:
			await collection.create_index(
				[(Session.FN.OAuth2.AccessToken, pymongo.ASCENDING)],
				unique=True,
				partialFilterExpression={
					Session.FN.OAuth2.AccessToken: {"$exists": True, "$gt": b""}}
			)
		except Exception as e:
			L.error("Failed to create index (access token): {}".format(e))

		# Cookie ID + client ID
		try:
			await collection.create_index(
				[
					(Session.FN.Cookie.Id, pymongo.ASCENDING),
					(Session.FN.OAuth2.ClientId, pymongo.ASCENDING),
				],
				unique=True,
				partialFilterExpression={
					Session.FN.Cookie.Id: {"$exists": True, "$gt": b""}}
			)
		except Exception as e:
			L.error("Failed to create compound index (cookie ID, client ID): {}".format(e))

		# Expiration descending
		# Optimizes deleting expired sessions
		try:
			await collection.create_index(
				[
					(Session.FN.Session.Expiration, pymongo.DESCENDING)
				]
			)
		except Exception as e:
			L.error("Failed to create index (expiration descending): {}".format(e))

		# Parent session
		# For searching session groups
		try:
			await collection.create_index(
				[
					(Session.FN.Session.ParentSessionId, pymongo.ASCENDING)
				]
			)
		except Exception as e:
			L.error("Failed to create index (parent session ID): {}".format(e))


	async def _on_housekeeping(self, event_name):
		await self._delete_expired_sessions()

	def _on_tick_metric(self, event_name):
		self.TaskService.schedule(self._metrics_task())

	async def _metrics_task(self):
		session_count = await self.count_sessions()
		self.SessionGauge.set("sessions", session_count)


	async def _delete_expired_sessions(self):
		# TODO: Improve performance - each self.delete(session_id) call searches for potential subsessions!
		expired = []
		async for session in self._iterate_raw(
			query_filter={
				Session.FN.Session.Expiration: {"$lt": datetime.datetime.now(datetime.timezone.utc)}}
		):
			expired.append(session["_id"])

		for sid in expired:
			# Use the delete method for proper session termination
			await self.delete(session_id=sid)

		if len(expired) > 0:
			L.log(asab.LOG_NOTICE, "Expired sessions deleted.", struct_data={"count": len(expired)})


	async def create_session(
		self,
		session_type: str,
		parent_session_id: bson.ObjectId = None,
		expiration: float | datetime.datetime = None,
		session_builders: list = None
	):
		upsertor = self.StorageService.upsertor(self.SessionCollection)

		# Set up required fields
		if session_type not in frozenset(["root", "openidconnect", "m2m", "cookie"]):
			L.error("Unsupported session type", struct_data={"type": session_type})
			return None
		upsertor.set(Session.FN.Session.Type, session_type)
		if parent_session_id is not None:
			upsertor.set(Session.FN.Session.ParentSessionId, parent_session_id)

		if expiration is None:
			expiration = self.Expiration
			expires = datetime.datetime.now(datetime.timezone.utc) + expiration
		elif isinstance(expiration, datetime.datetime):
			expires = expiration
			expiration = expires - datetime.datetime.now(datetime.timezone.utc)
		elif isinstance(expiration, datetime.timedelta):
			expires = datetime.datetime.now(datetime.timezone.utc) + expiration
		elif isinstance(expiration, (int, float)):
			expiration = datetime.timedelta(seconds=expiration)
			expires = datetime.datetime.now(datetime.timezone.utc) + expiration
		else:
			raise ValueError("Invalid expiration type: {}".format(type(expiration)))

		if expiration > self.MaximumAge:
			# TODO: Cut the expiration or raise error
			L.warning("Session expiration exceeds maximum session age.")
		max_expiration = datetime.datetime.now(datetime.timezone.utc) + self.MaximumAge
		if self.TouchExtensionSeconds is not None:
			touch_extension_seconds = self.TouchExtensionSeconds
		else:
			touch_extension_seconds = self.TouchExtensionRatio * expiration.total_seconds()

		upsertor.set(Session.FN.Session.Expiration, expires)
		upsertor.set(Session.FN.Session.MaxExpiration, max_expiration)
		upsertor.set(Session.FN.Session.ExpirationExtension, touch_extension_seconds)

		# Add builder fields
		if session_builders is None:
			session_builders = list()
		for session_builder in session_builders:
			for key, value in session_builder:
				if key in Session.EncryptedIdentifierFields and value is not None:
					value = Session.EncryptedPrefix + self.aes_encrypt(value)
					upsertor.set(key, value)
				else:
					upsertor.set(key, value, encrypt=(key in Session.EncryptedAttributes))

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
			version=session_dict["_v"],
		)

		for session_builder in session_builders:
			for key, value in session_builder:
				if key in Session.EncryptedIdentifierFields and value is not None:
					value = Session.EncryptedPrefix + self.aes_encrypt(value)
					upsertor.set(key, value)
				else:
					upsertor.set(key, value, encrypt=(key in Session.EncryptedAttributes))

		await upsertor.execute(event_type=EventTypes.SESSION_UPDATED)
		return await self.get(session_id)


	async def update_session_expiration(self, session_id: str, expires_at: datetime.datetime):
		assert expires_at is not None
		if isinstance(session_id, str):
			session_id = bson.ObjectId(session_id)
		session_dict = await self.StorageService.get(self.SessionCollection, session_id)

		upsertor = self.StorageService.upsertor(
			self.SessionCollection,
			obj_id=session_id,
			version=session_dict["_v"],
		)
		upsertor.set(Session.FN.Session.Expiration, expires_at)
		await upsertor.execute(event_type=EventTypes.SESSION_UPDATED)

		L.log(asab.LOG_NOTICE, "Session expiration updated.", struct_data={
			"sid": session_id,
			"type": session_dict.get(Session.FN.Session.Type),
		})
		return await self.get(session_id)


	async def get_by(self, key: str, value):
		# Encrypt sensitive fields
		if key in Session.EncryptedIdentifierFields:
			value = Session.EncryptedPrefix + self.aes_encrypt(value)

		try:
			session_dict = await self.StorageService.get_by(
				self.SessionCollection, key, value, decrypt=Session.EncryptedAttributes)
		except ValueError as e:
			# Likely a problem with obsolete decryption
			L.warning("ValueError when retrieving session: {}".format(e), struct_data={"key": key})
			raise exceptions.SessionNotFoundError("Session not found.", query={key: value})

		if session_dict is None:
			raise exceptions.SessionNotFoundError("Session not found.", query={key: value})

		# Do not return expired sessions
		expires_at = session_dict[Session.FN.Session.Expiration]
		if expires_at < datetime.datetime.now(datetime.timezone.utc):
			raise exceptions.SessionNotFoundError("Session expired.", query={key: value})

		session_dict = self._decrypt_encrypted_session_identifiers(session_dict)

		try:
			session = Session(session_dict)
		except Exception as e:
			L.exception("Failed to create Session from database object.", struct_data={
				"sid": session_dict.get("_id"),
			})
			raise exceptions.SessionNotFoundError("Session deserialization failed.", query={key: value}) from e

		return session


	async def get(self, session_id):
		if isinstance(session_id, str):
			session_id = bson.ObjectId(session_id)
		try:
			session_dict = await self.StorageService.get(
				self.SessionCollection, session_id, decrypt=Session.EncryptedAttributes)
		except KeyError:
			raise exceptions.SessionNotFoundError("Session not found.", session_id=session_id)
		except ValueError as e:
			# Likely a problem with obsolete decryption
			L.warning("ValueError when retrieving session: {}".format(e), struct_data={"sid": session_id})
			raise exceptions.SessionNotFoundError("Session not found.", session_id=session_id)

		# Do not return expired sessions
		if session_dict[Session.FN.Session.Expiration] < datetime.datetime.now(datetime.timezone.utc):
			raise exceptions.SessionNotFoundError("Session expired.", session_id=session_id)

		session_dict = self._decrypt_encrypted_session_identifiers(session_dict)

		try:
			session = Session(session_dict)
		except Exception as e:
			L.exception("Failed to create Session from database object.", struct_data={
				"sid": session_dict.get("_id"),
			})
			raise exceptions.SessionNotFoundError("Session deserialization failed.", session_id=session_id) from e
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


	async def list(self, page: int = 0, limit: int = None, query_filter=None, include_expired=False):
		collection = self.StorageService.Database[self.SessionCollection]

		if query_filter is None:
			query_filter = {}

		if not include_expired:
			query_filter[Session.FN.Session.Expiration] = {"$gt": datetime.datetime.now(datetime.timezone.utc)}

		sessions = []
		async for session_dict in self._iterate_raw(page, limit, query_filter):
			sessions.append(rest_get(session_dict))

		return {
			'data': sessions,
			'count': await collection.count_documents(query_filter)
		}


	async def recursive_list(self, page: int = 0, limit: int = None, query_filter=None, include_expired=False):
		"""
		List top-level sessions with all their children sessions inside the "children" attribute
		"""
		collection = self.StorageService.Database[self.SessionCollection]

		if query_filter is None:
			query_filter = {}

		if not include_expired:
			query_filter[Session.FN.Session.Expiration] = {"$gt": datetime.datetime.now(datetime.timezone.utc)}

		# Find only top-level sessions (with no parent)
		query_filter.update({Session.FN.Session.ParentSessionId: None})

		cursor = collection.find(query_filter)

		cursor.sort('_c', -1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		sessions = []
		count = await collection.count_documents(query_filter)
		async for session_dict in self._iterate_raw(page, limit, query_filter):
			try:
				session = Session(session_dict).rest_get()
			except Exception as e:
				L.error("Failed to create Session from database object: {}".format(e), struct_data={
					"sid": session_dict.get("_id"),
				})
				await self.delete(session_dict.get(Session.FN.SessionId))
				continue
			# Include children sessions
			children = await self.list(
				query_filter={Session.FN.Session.ParentSessionId: bson.ObjectId(session["_id"])},
				include_expired=include_expired,
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


	async def touch(
		self,
		session: Session,
		expires: datetime.datetime = None,
		*,
		override_cooldown: bool = False
	):
		"""
		Update session modification time to record activity.
		Also extend session expiration if possible.

		Return the updated session object.
		"""
		if not override_cooldown and (
			datetime.datetime.now(datetime.timezone.utc) < session.Session.ModifiedAt + self.TouchCooldown
		):
			# Session has been touched recently
			return session

		expires = self._calculate_extended_expiration(session, expires)

		# Extend root session
		if session.Session.ParentSessionId is not None:
			try:
				root_session = await self.get(session.Session.ParentSessionId)
				await self.touch(root_session, expires, override_cooldown=override_cooldown)
			except exceptions.SessionNotFoundError:
				L.info("Will not extend subsession expiration: Root session not found.", struct_data={
					"sid": session.Session.Id, "psid": session.Session.ParentSessionId})
				expires = None

		# Update session
		version = session.Session.Version
		upsertor = self.StorageService.upsertor(
			self.SessionCollection,
			session.SessionId,
			version=version
		)
		if expires is not None:
			upsertor.set(Session.FN.Session.Expiration, expires)
			L.info("Extending session expiration.", struct_data={
				"sid": session.Session.Id, "exp": expires, "v": version})

		try:
			await upsertor.execute(event_type=EventTypes.SESSION_EXTENDED)
		except KeyError:
			# This is often caused by a race condition when simultaneous requests attempt to touch the session.
			# It can be ignored.
			L.info("Conflict: Session already touched", struct_data={"sid": session.Session.Id, "v": version})

		return await self.get(session.SessionId)


	def _calculate_extended_expiration(self, session: Session, expires: datetime.datetime = None):
		if session.Session.Expiration >= session.Session.MaxExpiration:
			return None

		if expires is None:
			if session.Session.ExpirationExtension is None:
				# May be a legacy "machine credentials session". Do not extend.
				return None
			expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
				seconds=session.Session.ExpirationExtension)

		if expires < session.Session.Expiration:
			# Do not shorten the session!
			return None
		if session.Session.MaxExpiration is not None and expires > session.Session.MaxExpiration:
			# Do not cross maximum expiration
			expires = session.Session.MaxExpiration

		return expires


	async def delete(self, session_id):
		# Recursively delete all child sessions first
		query_filter = {Session.FN.Session.ParentSessionId: bson.ObjectId(session_id)}

		to_delete = []
		async for session_dict in self._iterate_raw(query_filter=query_filter):
			to_delete.append(session_dict)

		for session_dict in to_delete:
			await self.delete(session_dict["_id"])

		# Delete the session itself
		await self.StorageService.delete(self.SessionCollection, bson.ObjectId(session_id))
		L.log(asab.LOG_NOTICE, "Session deleted", struct_data={"sid": session_id})

		# Delete all the session's tokens
		await self.TokenService.delete_tokens_by_session_id(session_id)

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

			# Delete all the session's tokens
			await self.TokenService.delete_tokens_by_session_id(session_dict["_id"])

		L.log(asab.LOG_NOTICE, "Sessions deleted", struct_data={
			"deleted_count": deleted,
			"failed_count": failed
		})

	async def delete_sessions_by_credentials_id(self, credentials_id):
		await self._delete_sessions_by_filter(
			query_filter={Session.FN.Credentials.Id: credentials_id})


	async def delete_sessions_by_tenant_in_scope(self, tenant):
		await self._delete_sessions_by_filter(
			query_filter={"{}.{}".format(Session.FN.Authorization.Authz, tenant): {"$exists": True}})


	async def inherit_track_id_from_root(self, session: Session) -> Session:
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
					((Session.FN.Session.TrackId, uuid.uuid4().bytes),),
				]
				await self.update_session(
					session.SessionId,
					session_builders=sub_session_builders)
				session = await self.get(session.SessionId)
		return session


	async def inherit_or_generate_new_track_id(
		self, dst_session: Session, src_session: Session
	) -> Session:
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
			session_builders = [((Session.FN.Session.TrackId, uuid.uuid4().bytes),)]
			await self.update_session(dst_session.SessionId, session_builders)
			if root_session_id is not None:
				await self.update_session(root_session_id, session_builders)

		elif not src_session.is_anonymous():
			L.info("Cannot transfer Track ID: Source session is not anonymous.", struct_data={
				"src_sid": src_session.SessionId, "dst_sid": dst_session.SessionId})
			root_session_id = dst_session.Session.ParentSessionId
			session_builders = [((Session.FN.Session.TrackId, uuid.uuid4().bytes),)]
			await self.update_session(dst_session.SessionId, session_builders)
			if root_session_id is not None:
				await self.update_session(root_session_id, session_builders)

		elif src_session.OAuth2.ClientId != dst_session.OAuth2.ClientId:
			L.info("Cannot transfer Track ID: Mismatching client IDs.", struct_data={
				"src_clid": src_session.OAuth2.ClientId, "dst_clid": dst_session.OAuth2.ClientId})
			root_session_id = dst_session.Session.ParentSessionId
			session_builders = [((Session.FN.Session.TrackId, uuid.uuid4().bytes),)]
			await self.update_session(dst_session.SessionId, session_builders)
			if root_session_id is not None:
				await self.update_session(root_session_id, session_builders)

		elif src_session.TrackId is None:
			L.info("Cannot transfer Track ID: Source session has no Track ID.", struct_data={
				"src_sid": src_session.SessionId, "dst_sid": dst_session.SessionId})
			root_session_id = dst_session.Session.ParentSessionId
			session_builders = [((Session.FN.Session.TrackId, uuid.uuid4().bytes),)]
			await self.update_session(dst_session.SessionId, session_builders)
			if root_session_id is not None:
				await self.update_session(root_session_id, session_builders)

		elif not dst_session.is_anonymous():
			# The destination session is authenticated while the source one is anonymous
			# Transfer the track ID to the destination session and delete the source session
			assert dst_session.Session.ParentSessionId is not None
			session_builders = [((Session.FN.Session.TrackId, src_session.Session.TrackId),)]
			await self.update_session(dst_session.SessionId, session_builders)
			await self.update_session(dst_session.Session.ParentSessionId, session_builders)

		elif src_session.Session.Type != dst_session.Session.Type:
			# The source and the destination sessions are both anonymous but of a different type (cookie vs token)
			# Group them together under the same root session
			root_session_id = dst_session.Session.ParentSessionId or src_session.Session.ParentSessionId
			root_session_builders = [
				((Session.FN.Session.TrackId, src_session.Session.TrackId),),
			]
			if root_session_id is not None:
				# Update the root session
				root_session = await self.get(root_session_id)
				assert root_session.Session.TrackId is None
				await self.update_session(root_session_id, session_builders=root_session_builders)
			else:
				# Create a new root session
				root_session_builders.extend([
					((Session.FN.Credentials.Id, dst_session.Credentials.Id),),
					((Session.FN.Authentication.IsAnonymous, True),),
				])
				await self.create_session(
					"root", session_builders=root_session_builders, expiration=self.AnonymousExpiration)
			sub_session_builders = [
				((Session.FN.Session.ParentSessionId, root_session_id),),
				((Session.FN.Session.TrackId, src_session.Session.TrackId),),
			]
			await self.update_session(dst_session.SessionId, session_builders=sub_session_builders)
			await self.update_session(src_session.SessionId, session_builders=sub_session_builders)

		else:
			# The source and the destination sessions are both anonymous and of the same type (cookie or token)
			# There shouldn't be more than one anonymous session per credentials per client per type
			# Transfer the track ID and delete the source session
			assert dst_session.Session.ParentSessionId is None
			session_builders = [((Session.FN.Session.TrackId, src_session.Session.TrackId),)]
			old_session_group_id = src_session.Session.ParentSessionId or src_session.SessionId
			await self.delete(old_session_group_id)
			await self.update_session(dst_session.SessionId, session_builders)

		return await self.get(dst_session.SessionId)


	async def build_sso_root_session(
		self,
		credentials_id: str,
		login_descriptor: dict,
	):
		authentication_service = self.App.get_service("seacatauth.AuthenticationService")
		credentials_service = self.App.get_service("seacatauth.CredentialsService")
		tenant_service = self.App.get_service("seacatauth.TenantService")
		role_service = self.App.get_service("seacatauth.RoleService")

		scope = frozenset(["profile", "email", "phone"])
		ext_login_svc = self.App.get_service("seacatauth.ExternalLoginService")
		session_builders = [
			await credentials_session_builder(credentials_service, credentials_id, scope),
			authentication_session_builder(login_descriptor),
			await available_factors_session_builder(authentication_service, credentials_id),
			await external_login_session_builder(ext_login_svc, credentials_id),
			# TODO: SSO session should not need to have Authz data
			await authz_session_builder(
				tenant_service=tenant_service,
				role_service=role_service,
				credentials_id=credentials_id,
				tenants=None,  # Root session is tenant-agnostic
			),
			cookie_session_builder(),
		]
		return session_builders


	async def build_client_session(
		self,
		root_session: Session,
		client_id: str,
		scope: typing.Iterable[str],
		tenants: typing.Iterable[str] = None,
		nonce: typing.Optional[str] = None,
		redirect_uri: typing.Optional[str] = None,
	):
		authentication_service = self.App.get_service("seacatauth.AuthenticationService")
		external_login_service = self.App.get_service("seacatauth.ExternalLoginService")
		credentials_service = self.App.get_service("seacatauth.CredentialsService")
		tenant_service = self.App.get_service("seacatauth.TenantService")
		role_service = self.App.get_service("seacatauth.RoleService")
		batman_service = self.App.get_service("seacatauth.BatmanService")

		# TODO: Choose builders based on scope
		# Make sure dangerous resources are removed from impersonated sessions
		if root_session.Authentication.ImpersonatorSessionId is not None:
			exclude_resources = {ResourceId.SUPERUSER, ResourceId.IMPERSONATE}
		else:
			exclude_resources = set()

		session_builders = [
			await credentials_session_builder(credentials_service, root_session.Credentials.Id, scope),
			await authz_session_builder(
				tenant_service=tenant_service,
				role_service=role_service,
				credentials_id=root_session.Credentials.Id,
				tenants=tenants,
				exclude_resources=exclude_resources,
			)
		]

		session_builders.append([
			(Session.FN.Authentication.AuthnTime, root_session.Authentication.AuthnTime),
		])

		if "profile" in scope or "userinfo:authn" in scope or "userinfo:*" in scope:
			session_builders.append(
				await external_login_session_builder(external_login_service, root_session.Credentials.Id))
			session_builders.append(
				await available_factors_session_builder(authentication_service, root_session.Credentials.Id))
			session_builders.append([
				(Session.FN.Authentication.LoginDescriptor, root_session.Authentication.LoginDescriptor),
				(Session.FN.Authentication.LoginFactors, root_session.Authentication.LoginFactors),
			])

		if "batman" in scope:
			password = batman_service.generate_password(root_session.Credentials.Id)
			username = root_session.Credentials.Username
			basic_auth = base64.b64encode("{}:{}".format(username, password).encode("ascii"))
			session_builders.append([
				(Session.FN.Batman.Token, basic_auth),
			])

		session_builders.append(oauth2_session_builder(client_id, scope, nonce, redirect_uri=redirect_uri))

		# Obtain Track ID if there is any in the root session
		if root_session.TrackId is not None:
			session_builders.append(((Session.FN.Session.TrackId, root_session.TrackId),))

		# Transfer impersonation data
		if root_session.Authentication.ImpersonatorSessionId is not None:
			session_builders.append((
				(
					Session.FN.Authentication.ImpersonatorSessionId,
					root_session.Authentication.ImpersonatorSessionId
				),
				(
					Session.FN.Authentication.ImpersonatorCredentialsId,
					root_session.Authentication.ImpersonatorCredentialsId
				),
			))

		return session_builders


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


	def _decrypt_encrypted_session_identifiers(self, session_dict: dict) -> dict:
		for field in Session.EncryptedIdentifierFields:
			# BACK COMPAT: Handle nested dictionaries
			obj = session_dict
			keys = field.split(".")
			for key in keys[:-1]:
				if key not in obj:
					break
				obj = obj[key]
			else:
				# BACK COMPAT: Keep values without prefix raw
				# TODO: Remove support once proper m2m tokens are in place
				value = obj.get(keys[-1])
				if value is not None and value.startswith(Session.EncryptedPrefix):
					obj[keys[-1]] = self.aes_decrypt(value[len(Session.EncryptedPrefix):])
		return session_dict
