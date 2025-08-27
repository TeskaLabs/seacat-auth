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
	TOKEN_TYPE = "ApiKey"

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
		if isinstance(query_filter, str):
			query_filter = {Session.FN.Session.Label: {"$regex": query_filter, "$options": "i"}}
		query_filter = {
			Session.FN.Session.Type: "apikey",
			**(query_filter or {})
		}
		tenant = asab.contextvars.Tenant.get()
		authz = asab.contextvars.Authz.get()
		if tenant is not None:
			query_filter["{}.{}".format(Session.FN.Authorization.Authz, tenant)] = {
				"$exists": True
			}
		else:
			# Only superuser can see data from all tenants
			authz.require_superuser_access()

		data = []
		async for session in self.SessionService.iterate_sessions(
			page,
			limit,
			query_filter=query_filter
		):
			data.append(_normalize_api_key(session))
		return data


	@asab.web.auth.require(ResourceId.APIKEY_ACCESS)
	async def get_api_key(self, key_id: str):
		try:
			session = await self.SessionService.get(session_id=key_id)
			return _normalize_api_key(session)
		except exceptions.SessionNotFoundError:
			raise exceptions.ApiKeyNotFoundError(key_id) from None


	@asab.web.auth.require(ResourceId.APIKEY_MANAGE)
	async def create_api_key(
		self, *,
		tenant: typing.Union[str, None],
		resources: typing.Set[str],
		expires_at: typing.Optional[datetime.datetime] = None,
		label: typing.Optional[str] = None,
	):
		expires_at = expires_at or datetime.datetime.now(datetime.UTC) + self.DefaultExpiration
		# Ensure that the agent has access to the requested resources
		agent_authz = asab.contextvars.Authz.get()
		if tenant is not None:
			with asab.contextvars.tenant_context(tenant):
				agent_authz.require_tenant_access()
				if len(resources) > 0:
					agent_authz.require_resource_access(*resources)
					for resource_id in resources:
						# Ensure resource exists and is not global-only
						resource = await self.ResourceService.get(resource_id)
						if resource.get("global_only", False) is True:
							L.error(
								"Global-only resource cannot be authorized in tenant context.",
								struct_data={"resource_id": resource_id}
							)
							raise asab.exceptions.AccessDeniedError()

				api_key_authz = {tenant: list(resources)}
		else:
			# Only superuser can create global (tenantless) API keys
			agent_authz.require_superuser_access()
			if len(resources) > 0:
				agent_authz.require_resource_access(*resources)
				for resource_id in resources:
					# Ensure resource exists
					await self.ResourceService.get(resource_id)

			api_key_authz = {"*": list(resources)}

		# Create session
		session_id = bson.ObjectId()
		credentials_id = "seacatauth:apikey"
		session = await self.SessionService.create_session(
			session_id=session_id,
			session_type="apikey",
			expiration=expires_at,
			session_builders=[[
				(Session.FN.Credentials.Id, credentials_id),
				(Session.FN.Session.Label, label),
				(Session.FN.Authorization.Authz, api_key_authz),
			]]
		)

		# Create token
		raw_value = await self.TokenService.create(
			token_length=self.TokenLength,
			token_type="apikey",
			session_id=session.Session.Id,
			expires_at=expires_at,
		)

		# Return token response
		return {
			"_id": session.Session.Id,
			"exp": session.Session.Expiration,
			"token_type": self.TOKEN_TYPE,
			"token_value": base64.urlsafe_b64encode(raw_value).decode("ascii"),
		}


	@asab.web.auth.require(ResourceId.APIKEY_MANAGE)
	async def delete_api_key(self, key_id: str):
		authz = asab.contextvars.Authz.get()
		if not authz.has_superuser_access():
			tenant = asab.contextvars.Tenant.get()
			apikey = await self.get_api_key(key_id)
			if tenant != apikey["tenant"]:
				L.error("Cannot delete API key from different tenant.", struct_data={
					"key_id": key_id,
					"key_tenant": apikey["tenant"],
					"agent_tenant": tenant,
				})
				raise exceptions.ApiKeyNotFoundError(key_id)

		try:
			await self.SessionService.delete(session_id=key_id)
		except exceptions.SessionNotFoundError:
			raise exceptions.ApiKeyNotFoundError(key_id) from None


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
			raise exceptions.SessionNotFoundError("Invalid or expired API key") from None

		try:
			session = await self.SessionService.get(token_data["sid"])
		except exceptions.SessionNotFoundError:
			L.error("Integrity error: API key points to a nonexistent session.", struct_data={
				"sid": token_data["sid"]})
			await self.TokenService.delete(token_bytes)
			raise exceptions.SessionNotFoundError("API key points to a nonexistent session") from None

		return session


def _normalize_api_key(session: Session) -> dict:
	for k, v in session.Authorization.Authz.items():
		if k != "*":
			tenant = k
			resources = v
			break
	else:
		# Global (tenantless) API key
		tenant = None
		resources = session.Authorization.Authz.get("*", [])

	api_key = {
		"_id": session.Session.Id,
		"_c": session.Session.CreatedAt,
		"cid": session.Credentials.Id,
		"exp": session.Session.Expiration,
		"tenant": tenant,
		"resources": resources,
		"label": session.Session.Label,
	}
	return api_key
