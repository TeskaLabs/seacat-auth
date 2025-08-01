import base64
import binascii
import datetime
import logging
import typing
import asab.storage.exceptions
import asab.exceptions
import asab.utils
import asab.web.auth
import asab.contextvars
import bson

from .. import exceptions
from ..models import Session
from ..models.const import ResourceId


L = logging.getLogger(__name__)


class ApiKeyService(asab.Service):
	"""
	API key management
	"""

	def __init__(self, app, service_name="seacatauth.ApiKeyService"):
		super().__init__(app, service_name)
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.TokenService = app.get_service("seacatauth.SessionTokenService")

		self.TenantService = app.get_service("seacatauth.TenantService")
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.ResourceService = app.get_service("seacatauth.ResourceService")

		self.DefaultExpiration = datetime.timedelta(
			seconds=asab.Config.getseconds("seacatauth:api_key", "default_expiration"))
		self.TokenLength = asab.Config.getint("seacatauth:api_key", "token_length")


	@asab.web.auth.require(ResourceId.APIKEY_ACCESS)
	async def iterate_api_keys(
		self,
		page: int = 0,
		limit: int = None,
		query_filter: typing.Optional[str | typing.Dict] = None,
	):
		data = []
		async for session in self.SessionService.iterate_sessions(
			page,
			limit,
			query_filter={
				Session.FN.Session.Type: "apikey",
				**(query_filter or {})
			}
		):
			data.append(_normalize_api_key(session))
		return data


	@asab.web.auth.require(ResourceId.APIKEY_ACCESS)
	async def get_api_key(self, key_id: str):
		session = await self.SessionService.get(session_id=key_id)
		return _normalize_api_key(session)


	@asab.web.auth.require(ResourceId.APIKEY_EDIT)
	async def create_api_key(
		self, *,
		authz: typing.Dict[str, typing.Set[str]],
		expires_at: typing.Optional[datetime.datetime] = None,
		label: typing.Optional[str] = None,
	):
		expires_at = expires_at or datetime.datetime.now(datetime.UTC) + self.DefaultExpiration
		# Ensure that the agent has access to the requested resources
		for tenant, resources in authz.items():
			if tenant != "*":
				with asab.contextvars.tenant_context(tenant):
					authz_obj = asab.contextvars.Authz.get()
					authz_obj.require_resource_access(*resources)

		# Create session
		session_id = bson.ObjectId()
		credentials_id = "seacatauth:apikey:{}".format(session_id)
		session = await self.SessionService.create_session(
			session_id=session_id,
			session_type="apikey",
			expiration=expires_at,
			session_builders=[[
				(Session.FN.Credentials.Id, credentials_id),
				(Session.FN.Session.Label, label),
				(Session.FN.Authorization.Authz, authz),
			]]
		)

		# Create token
		raw_value = await self.TokenService.create(
			token_length=32,
			token_type="apikey",
			session_id=session.Session.Id,
			expires_at=expires_at,
		)

		# Return token response
		return {
			"_id": session.Session.Id,
			"exp": session.Session.Expiration,
			"token_type": "ApiKey",
			"token_value": base64.urlsafe_b64encode(raw_value).decode("ascii"),
		}


	@asab.web.auth.require(ResourceId.APIKEY_EDIT)
	async def update_api_key(
		self, *,
		key_id: str,
		label: typing.Optional[str] = None,
	):
		await self.SessionService.update_session(
			session_id=key_id,
			session_builders=[(Session.FN.Session.Label, label)]
		)


	@asab.web.auth.require(ResourceId.APIKEY_EDIT)
	async def delete_api_key(self, key_id: str):
		await self.SessionService.delete(session_id=key_id)


	async def get_session_by_api_key(self, token_value: str) -> Session:
		try:
			token_bytes = base64.urlsafe_b64decode(token_value.encode("ascii"))
		except binascii.Error as e:
			L.error("Corrupt API key format: Base64 decoding failed.", struct_data={
				"token_value": token_value})
			raise exceptions.SessionNotFoundError("Corrupt API key format") from e
		except UnicodeEncodeError as e:
			L.error("Corrupt API key format: ASCII decoding failed.", struct_data={
				"token_value": token_value})
			raise exceptions.SessionNotFoundError("Corrupt API key format") from e

		try:
			token_data = await self.TokenService.get(token_bytes, token_type="apikey")
		except KeyError:
			raise exceptions.SessionNotFoundError("Invalid or expired API key")

		try:
			session = await self.SessionService.get(token_data["sid"])
		except KeyError:
			L.error("Integrity error: API key points to a nonexistent session.", struct_data={
				"sid": token_data["sid"]})
			await self.TokenService.delete(token_bytes)
			raise exceptions.SessionNotFoundError("API key points to a nonexistent session")

		return session


def _normalize_api_key(session: Session) -> dict:
	api_key = {
		"_id": session.Session.Id,
		"_c": session.Session.CreatedAt,
		"cid": session.Credentials.Id,
		"exp": session.Session.Expiration,
		"resources": session.Authorization.Authz,
	}
	if session.Session.Label:
		api_key["label"] = session.Session.Label
	return api_key
