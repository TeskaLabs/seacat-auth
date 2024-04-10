import base64
import datetime
import logging
import secrets
import hashlib
import typing

import asab.storage
import pymongo

from ..events import EventTypes

#

L = logging.getLogger(__name__)

#


class AuthTokenField:
	TokenType = "t"
	SessionId = "sid"
	IsSessionAlgorithmic = "sa"
	ExpiresAt = "exp"
	CodeChallenge = "cc"
	CodeChallengeMethod = "ccm"
	Version = "_v"


class AuthTokenService(asab.Service):
	"""
	Create and manage securely hashed session identifiers (tokens)
	"""

	AuthTokenCollection = "at"
	OAuthRefreshTokenLength = 36
	OAuthAuthorizationCodeLength = 36
	OAuthAccessTokenLength = 36
	CookieLength = 36

	def __init__(self, app, service_name="seacatauth.AuthTokenService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		app.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)


	async def initialize(self, app):
		collection = await self.StorageService.collection(self.AuthTokenCollection)
		try:
			await collection.create_index([(AuthTokenField.SessionId, pymongo.ASCENDING)])
		except Exception as e:
			L.error("Failed to create secondary index (session ID): {}".format(e))


	async def _on_housekeeping(self, event_name):
		await self._delete_expired_tokens()


	async def create(
		self, token_length: int, token_type: str, session_id: str,
		expiration: typing.Optional[float] = None,
		is_session_algorithmic: bool = False,
		**kwargs
	) -> bytes:
		"""
		Create and store a new auth token

		@param token_length: Number of token bytes
		@param token_type: Token type string
		@param session_id: Session identifier
		@param expiration: Expiration in seconds
		@param is_session_algorithmic: Whether the session is algorithmic
		@return: Raw token value
		"""
		token = _generate_token(token_length)
		token_hash = _hash_token(token)
		upsertor = self.StorageService.upsertor(self.AuthTokenCollection, obj_id=token_hash)

		upsertor.set(AuthTokenField.TokenType, token_type)
		upsertor.set(AuthTokenField.SessionId, session_id)
		if is_session_algorithmic:
			upsertor.set(AuthTokenField.IsSessionAlgorithmic, is_session_algorithmic)
		if expiration:
			expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=expiration)
			upsertor.set(AuthTokenField.ExpiresAt, expires_at)
		for k, v in kwargs.items():
			if v is not None:
				upsertor.set(k, v)

		await upsertor.execute(event_type=EventTypes.AUTH_TOKEN_CREATED)
		L.log(asab.LOG_NOTICE, "Auth token created.", struct_data={"sid": session_id, "type": token_type})

		return token


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
		data = await self.StorageService.get(self.AuthTokenCollection, token_hash)
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
		data = await self.StorageService.get(self.AuthTokenCollection, _hash_token(token))
		upsertor = self.StorageService.upsertor(
			self.AuthTokenCollection,
			obj_id=_hash_token(token),
			version=data[AuthTokenField.Version]
		)
		expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=expiration)
		upsertor.set(AuthTokenField.ExpiresAt, expires_at)
		await upsertor.execute(event_type=EventTypes.AUTH_TOKEN_EXTENDED)
		L.log(asab.LOG_NOTICE, "Auth token validity extended.", struct_data={
			"sid": data[AuthTokenField.SessionId], "type": data[AuthTokenField.TokenType]})
		return data


	async def delete(self, token: bytes):
		"""
		Delete auth token

		@param token: Token bytes
		@return:
		"""
		await self.StorageService.delete(self.AuthTokenCollection, _hash_token(token))


	async def _delete_expired_tokens(self):
		"""
		Delete expired auth tokens
		"""
		collection = self.StorageService.Database[self.AuthTokenCollection]
		query_filter = {AuthTokenField.ExpiresAt: {"$lt": datetime.datetime.now(datetime.timezone.utc)}}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.log(asab.LOG_NOTICE, "Expired auth tokens deleted.", struct_data={
				"count": result.deleted_count
			})


	async def delete_tokens_by_session_id(self, session_id: str):
		"""
		Delete all of session's auth tokens
		"""
		collection = self.StorageService.Database[self.AuthTokenCollection]
		query_filter = {AuthTokenField.SessionId: session_id}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.log(asab.LOG_NOTICE, "Session's auth tokens deleted.", struct_data={
				"sid": session_id,
				"count": result.deleted_count,
			})


def _is_token_valid(token_data: dict):
	return (
		AuthTokenField.ExpiresAt in token_data
		and token_data[AuthTokenField.ExpiresAt] > datetime.datetime.now(datetime.UTC)
	)


def _hash_token(token: bytes):
	return hashlib.sha256(token).digest()


def _generate_token(token_length: int):
	return secrets.token_bytes(token_length)
