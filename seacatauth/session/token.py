import datetime
import logging
import secrets
import hashlib
import typing

import asab.storage
import bson
import pymongo

from ..events import EventTypes

#

L = logging.getLogger(__name__)

#


class SessionTokenField:
	TokenType = "t"
	SessionId = "sid"
	IsSessionAlgorithmic = "sa"
	ExpiresAt = "exp"
	CodeChallenge = "cc"
	CodeChallengeMethod = "ccm"
	Version = "_v"


class SessionTokenService(asab.Service):
	"""
	Create and manage securely hashed session identifiers (tokens)
	"""

	SessionTokenCollection = "st"
	OAuthRefreshTokenLength = 36
	OAuthAuthorizationCodeLength = 36
	OAuthAccessTokenLength = 36
	CookieLength = 36

	def __init__(self, app, service_name="seacatauth.SessionTokenService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		app.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)


	async def initialize(self, app):
		collection = await self.StorageService.collection(self.SessionTokenCollection)
		try:
			await collection.create_index([(SessionTokenField.SessionId, pymongo.ASCENDING)])
		except Exception as e:
			L.error("Failed to create secondary index (session ID): {}".format(e), struct_data={
				"collection": self.SessionTokenCollection})


	async def _on_housekeeping(self, event_name):
		await self._delete_expired_tokens()


	async def create(
		self, token_length: int, token_type: str, session_id: str,
		expiration: typing.Optional[float] = None,
		is_session_algorithmic: bool = False,
		**kwargs
	) -> typing.Tuple[bytes, datetime.datetime]:
		"""
		Create and store a new auth token

		@param token_length: Number of token bytes
		@param token_type: Token type string
		@param session_id: Session identifier
		@param expiration: Token lifetime
		@param is_session_algorithmic: Whether the session is algorithmic
		@return: Raw token value
		"""
		token = _generate_token(token_length)
		token_hash = _hash_token(token)
		upsertor = self.StorageService.upsertor(self.SessionTokenCollection, obj_id=token_hash)

		upsertor.set(SessionTokenField.TokenType, token_type)
		upsertor.set(SessionTokenField.SessionId, session_id)
		if is_session_algorithmic:
			upsertor.set(SessionTokenField.IsSessionAlgorithmic, is_session_algorithmic)
		if expiration:
			expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=expiration)
			upsertor.set(SessionTokenField.ExpiresAt, expires_at)
		for k, v in kwargs.items():
			if v is not None:
				upsertor.set(k, v)

		await upsertor.execute(event_type=EventTypes.AUTH_TOKEN_CREATED)
		L.info("Session token created.", struct_data={"sid": session_id, "type": token_type, "exp": expires_at})

		return token, expires_at


	async def get(
		self, token: bytes,
		token_type: typing.Optional[str] = None,
	):
		"""
		Get auth token

		@param token: Token bytes
		@param token_type: Type of the token
		@return:
		"""
		token_hash = _hash_token(token)
		data = await self.StorageService.get(self.SessionTokenCollection, token_hash)
		if not _is_token_valid(data):
			raise KeyError("Auth token expired.")
		if token_type is not None and data["t"] != token_type:
			raise KeyError("Auth token type does not match.")
		return data


	async def extend(self, token: bytes, expiration: float):
		"""
		Extend auth token validity

		@param token: Raw token value
		@param expiration: Expiration in seconds
		@return:
		"""
		data = await self.StorageService.get(self.SessionTokenCollection, _hash_token(token))
		upsertor = self.StorageService.upsertor(
			self.SessionTokenCollection,
			obj_id=_hash_token(token),
			version=data[SessionTokenField.Version]
		)
		expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=expiration)
		upsertor.set(SessionTokenField.ExpiresAt, expires_at)
		await upsertor.execute(event_type=EventTypes.AUTH_TOKEN_EXTENDED)
		L.info("Session token validity extended.", struct_data={
			"sid": data[SessionTokenField.SessionId], "type": data[SessionTokenField.TokenType]})
		return data


	async def delete(self, token: bytes):
		"""
		Delete auth token

		@param token: Token bytes
		@return:
		"""
		collection = self.StorageService.Database[self.SessionTokenCollection]
		token_data = await collection.find_one_and_delete(filter={"_id": _hash_token(token)})
		L.info("Session token deleted.", struct_data={
			"sid": token_data[SessionTokenField.SessionId], "type": token_data[SessionTokenField.TokenType]})


	async def _delete_expired_tokens(self):
		"""
		Delete expired auth tokens
		"""
		collection = self.StorageService.Database[self.SessionTokenCollection]
		query_filter = {SessionTokenField.ExpiresAt: {"$lt": datetime.datetime.now(datetime.timezone.utc)}}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.log(asab.LOG_NOTICE, "Expired session tokens deleted.", struct_data={
				"count": result.deleted_count
			})


	async def delete_tokens_by_session_id(self, session_id: str):
		"""
		Delete all of session's auth tokens
		"""
		collection = self.StorageService.Database[self.SessionTokenCollection]
		query_filter = {SessionTokenField.SessionId: bson.ObjectId(session_id)}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.log(asab.LOG_NOTICE, "Session tokens deleted.", struct_data={
				"sid": session_id,
				"count": result.deleted_count,
			})


def _is_token_valid(token_data: dict):
	return (
		SessionTokenField.ExpiresAt in token_data
		and token_data[SessionTokenField.ExpiresAt] > datetime.datetime.now(datetime.UTC)
	)


def _hash_token(token: bytes):
	return hashlib.sha256(token).digest()


def _generate_token(token_length: int):
	return secrets.token_bytes(token_length)
