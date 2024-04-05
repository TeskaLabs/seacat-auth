import base64
import datetime
import logging
import secrets
import hashlib
import typing

import asab.storage
from ..events import EventTypes

#

L = logging.getLogger(__name__)

#


class AuthTokenType:
	OAuthRefreshToken = "ort"
	OAuthAuthorizationCode = "oac"  # TODO: Move authorization code here
	OAuthAccessToken = "oat"  # TODO: Move access tokens here (consider performance first!)
	Cookie = "c"  # TODO: Move auth cookies here (consider performance first!)


class AuthTokenField:
	TokenType = "t"
	SessionId = "sid"
	ExpiresAt = "exp"
	Version = "_v"


class AuthTokenService(asab.Service):
	"""
	Create and manage securely hashed session identifiers (tokens)
	"""

	AuthTokenCollection = "at"
	OAuthRefreshTokenLength = 32
	OAuthAuthorizationCodeLength = 32
	OAuthAccessTokenLength = 32
	CookieLength = 32

	def __init__(self, app, service_name="seacatauth.AuthTokenService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		app.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)


	async def _on_housekeeping(self, event_name):
		await self._delete_expired_tokens()


	async def create_oauth_authorization_code(
		self, session_id: str, expiration: float,
		code_challenge: str | None = None,
		code_challenge_method: str | None = None
	):
		"""
		Create OAuth2 authorization code

		@param session_id: Session identifier
		@param expiration: Expiration in seconds
		@param code_challenge: PKCE challenge string
		@param code_challenge_method: PKCE verification method
		@return: Base64-encoded token value
		"""
		raw_value = await self._create_token(
			token_length=self.OAuthAuthorizationCodeLength,
			token_type=AuthTokenType.OAuthAuthorizationCode,
			session_id=session_id,
			expiration=expiration,
			code_challenge=code_challenge,
			code_challenge_method=code_challenge_method,
		)
		return base64.urlsafe_b64encode(raw_value).decode("ascii")


	async def create_oauth_access_token(self, session_id: str, expiration: float):
		"""
		Create OAuth2 access token

		@param session_id: Session identifier
		@param expiration: Expiration in seconds
		@return: Base64-encoded token value
		"""
		raw_value = await self._create_token(
			token_length=self.OAuthAccessTokenLength,
			token_type=AuthTokenType.OAuthAccessToken,
			session_id=session_id,
			expiration=expiration,
		)
		return base64.urlsafe_b64encode(raw_value).decode("ascii")


	async def create_oauth_refresh_token(self, session_id: str, expiration: float):
		"""
		Create OAuth2 refresh token

		@param session_id: Session identifier
		@return: Base64-encoded token value
		"""
		raw_value = await self._create_token(
			token_length=self.OAuthRefreshTokenLength,
			token_type=AuthTokenType.OAuthRefreshToken,
			session_id=session_id,
			expiration=expiration,
		)
		return base64.urlsafe_b64encode(raw_value).decode("ascii")


	async def create_cookie(self, session_id: str, expiration: float):
		"""
		Create HTTP cookie value

		@param session_id: Session identifier
		@param expiration: Expiration in seconds
		@return: Base64-encoded token value
		"""
		raw_value = await self._create_token(
			token_length=self.CookieLength,
			token_type=AuthTokenType.OAuthAccessToken,
			session_id=session_id,
			expiration=expiration,
		)
		return base64.urlsafe_b64encode(raw_value).decode("ascii")


	async def _create_token(
		self, token_length: int, token_type: str, session_id: str,
		expiration: typing.Optional[float] = None,
		**kwargs
	):
		"""
		Create and store a new auth token

		@param token_length: Number of token bytes
		@param token_type: Token type string
		@param session_id: Session identifier
		@param expiration: Expiration in seconds
		@return: Raw token value
		"""
		token = _generate_token(token_length)
		upsertor = self.StorageService.upsertor(self.AuthTokenCollection, obj_id=_hash_token(token))

		upsertor.set(AuthTokenField.TokenType, token_type)
		upsertor.set(AuthTokenField.SessionId, session_id)
		if expiration:
			expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=expiration)
			upsertor.set(AuthTokenField.ExpiresAt, expires_at)
		for k, v in kwargs.items():
			if v is not None:
				upsertor.set(k, v)

		await upsertor.execute(event_type=EventTypes.AUTH_TOKEN_CREATED)
		L.log(asab.LOG_NOTICE, "Auth token created.", struct_data={"sid": session_id, "type": token_type})

		return token


	async def get_by_oauth2_access_token(self, token: bytes):
		"""
		Get access token data

		@param token: Raw token value
		@return:
		"""
		return await self.get(token, AuthTokenType.OAuthAccessToken)


	async def get_by_oauth2_refresh_token(self, token: bytes):
		"""
		Get refresh token data

		@param token: Raw token value
		@return:
		"""
		return await self.get(token, AuthTokenType.OAuthRefreshToken)


	async def get_by_oauth2_authorization_code(self, token: bytes):
		"""
		Get authorization code data

		@param token: Raw token value
		@return:
		"""
		return await self.get(token, AuthTokenType.OAuthAuthorizationCode)


	async def get_by_cookie(self, token: bytes):
		"""
		Get cookie data

		@param token: Raw token value
		@return:
		"""
		return await self.get(token, AuthTokenType.Cookie)


	async def get(self, token: bytes, token_type: str | None = None):
		"""
		Get auth token

		@param token: Raw token value
		@return:
		"""
		data = await self.StorageService.get(self.AuthTokenCollection, _hash_token(token))
		if not _is_valid(data):
			raise KeyError("Auth token expired.")
		if token_type is not None and data["t"] != token_type:
			raise KeyError("Auth token type does not match.")
		return data


	async def extend_token(self, token: bytes, expiration: float):
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

		@param token: Raw token value
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


	async def _delete_tokens_by_session_id(self, session_id: str):
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


def _is_valid(token_data: dict):
	return (
		AuthTokenField.ExpiresAt in token_data
		and token_data[AuthTokenField.ExpiresAt] < datetime.datetime.now(datetime.UTC)
	)


def _hash_token(token: bytes):
	return hashlib.sha256(token).digest()


def _generate_token(token_length: int):
	return secrets.token_bytes(token_length)
