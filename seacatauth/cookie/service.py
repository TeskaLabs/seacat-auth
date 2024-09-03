import base64
import datetime
import hashlib
import re
import logging
import typing

import aiohttp
import asab
import asab.web
import asab.storage
import asab.exceptions

from ..contextvars import AccessIps
from .. import exceptions, generic
from ..session.adapter import SessionAdapter, CookieData
from ..session.builders import cookie_session_builder
from ..authz import build_credentials_authz
from .. import AuditLogger

#

L = logging.getLogger(__name__)

#


class CookieToken:
	TokenType = "ct"
	ByteLength = asab.Config.getint("cookie", "token_length")
	Expiration = asab.Config.getseconds("cookie", "expiration")


class CookieService(asab.Service):
	"""
	Manage cookie sessions
	"""

	def __init__(self, app, service_name="seacatauth.CookieService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.TokenService = app.get_service("seacatauth.SessionTokenService")
		self.AuthenticationService = None
		self.OpenIdConnectService = None

		# Configure root cookie
		self.CookieName = asab.Config.get("seacatauth:cookie", "name")
		self.CookiePattern = re.compile(
			"(^{cookie}({client_suffix})?=[^;]*; ?"
			"|; ?{cookie}({client_suffix})?=[^;]*"
			"|^{cookie}({client_suffix})?=[^;]*)".format(cookie=self.CookieName, client_suffix=r"_[A-Z8-9]+")
		)
		self.CookieSecure = asab.Config.getboolean("seacatauth:cookie", "secure")
		self.RootCookieDomain = asab.Config.get("seacatauth:cookie", "domain") or None
		if self.RootCookieDomain is not None:
			self.RootCookieDomain = self._validate_cookie_domain(self.RootCookieDomain)

		self.AuthWebUiBaseUrl = app.AuthWebUiUrl.rstrip("/")


	async def initialize(self, app):
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")
		self.OpenIdConnectService = self.App.get_service("seacatauth.OpenIdConnectService")


	def get_cookie_name(self, client_id: str = None):
		if client_id is not None:
			client_id_hash = base64.b32encode(
				hashlib.sha256(client_id.encode("ascii")).digest()[:10]
			).decode("ascii")
			cookie_name = "{}_{}".format(self.CookieName, client_id_hash)
		else:
			cookie_name = self.CookieName
		return cookie_name


	def remove_seacat_cookies_from_request(self, cookie_string):
		return self.CookiePattern.sub("", cookie_string)


	@staticmethod
	def _validate_cookie_domain(domain):
		if not domain.isascii():
			raise ValueError("Cookie domain can contain only ASCII characters.")
		domain = domain.lstrip(".")
		return domain or None


	def get_session_cookie_value(self, request, client_id=None):
		"""
		Get Seacat session cookie value from request header
		"""
		cookie_name = self.get_cookie_name(client_id)
		cookie = request.cookies.get(cookie_name)
		return cookie


	async def get_session_by_request_cookie(self, request, client_id=None):
		"""
		Find session by the combination of SCI (cookie ID) and client ID

		To search for root session, keep client_id=None.
		Root sessions have no client_id attribute, which MongoDB matches as None.
		"""
		session_cookie_id = self.get_session_cookie_value(request, client_id)
		if session_cookie_id is None:
			raise exceptions.NoCookieError(client_id)
		return await self.get_session_by_session_cookie_value(session_cookie_id)


	async def get_session_by_session_cookie_value(self, cookie_value: str):
		"""
		Get session by cookie value.
		"""
		if "." in cookie_value:
			# If there is ".", the value is not pure base64. It must be a JWT of an algorithmic session.
			return await self.SessionService.Algorithmic.deserialize(cookie_value)

		# Then try looking for the session in the database
		try:
			cookie_value = base64.urlsafe_b64decode(cookie_value.encode("ascii"))
		except ValueError as e:
			raise exceptions.SessionNotFoundError(
				"Cookie value is not base64", query={"cookie_value": cookie_value}) from e

		try:
			session = await self.SessionService.get_by(SessionAdapter.FN.Cookie.Id, cookie_value)
		except KeyError as e:
			raise exceptions.SessionNotFoundError(
				"Session not found", query={"cookie_value": cookie_value}) from e
		except ValueError as e:
			raise exceptions.SessionNotFoundError(
				"Error deserializing session", query={"cookie_value": cookie_value}) from e

		return session


	async def create_cookie_client_session(
		self, root_session, client_id, scope,
		nonce=None,
		redirect_uri=None,
		tenants=None,
		requested_expiration=None
	):
		"""
		Create a new cookie-based session
		"""
		# Check if the Client exists
		client_svc = self.App.get_service("seacatauth.ClientService")
		try:
			await client_svc.get(client_id)
		except KeyError:
			raise KeyError("Client '{}' not found".format(client_id))

		# Build the session
		session_builders = await self.SessionService.build_client_session(
			root_session,
			client_id=client_id,
			scope=scope,
			tenants=tenants,
			nonce=nonce,
			redirect_uri=redirect_uri,
		)

		session = await self.SessionService.create_session(
			session_type="cookie",
			parent_session_id=root_session.SessionId,
			expiration=requested_expiration,
			session_builders=session_builders,
		)

		return session


	async def create_anonymous_cookie_client_session(
		self, anonymous_cid: str, client_dict: dict, scope: list,
		track_id: bytes = None,
		tenants: list = None,
		redirect_uri: str = None,
		from_info=None,
	):
		"""
		Create a new anonymous cookie-based session
		"""
		session_svc = self.App.get_service("seacatauth.SessionService")

		session = await session_svc.Algorithmic.create_anonymous_session(
			created_at=datetime.datetime.now(datetime.timezone.utc),
			track_id=track_id,
			client_dict=client_dict,
			scope=scope,
			redirect_uri=redirect_uri,
		)

		session.Cookie = CookieData(
			Id=session_svc.Algorithmic.serialize(session),
			Domain=client_dict.get("cookie_domain") or None)

		AuditLogger.log(asab.LOG_NOTICE, "Authentication successful", struct_data={
			"anonymous": True,
			"cid": anonymous_cid,
			"client_id": client_dict["_id"],
			"track_id": track_id,
			"fi": from_info})

		return session


	async def extend_session_expiration(self, session: SessionAdapter, client: dict = None):
		expiration = client.get("session_expiration") if client else None
		if expiration:
			expiration = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=expiration)
		else:
			expiration = datetime.datetime.now(datetime.UTC) + self.SessionService.Expiration

		return await self.SessionService.touch(session, expiration, override_cooldown=True)


	def set_session_cookie(self, response, cookie_value, client_id=None, cookie_domain=None, secure=None):
		"""
		Add a Set-Cookie header to the response.
		The cookie serves as a Seacat Auth session identifier and is used for authentication.
		"""
		cookie_name = self.get_cookie_name(client_id)
		cookie_domain = cookie_domain or self.RootCookieDomain
		if secure is None:
			secure = self.CookieSecure

		response.set_cookie(
			cookie_name,
			cookie_value,
			httponly=True,  # Not accessible from Javascript
			domain=cookie_domain,
			secure=secure,
		)


	def delete_session_cookie(self, response, client_id: typing.Optional[str] = None):
		"""
		Add a Set-Cookie header to the response to unset Seacat Session cookie
		"""
		cookie_name = self.get_cookie_name(client_id)
		response.del_cookie(cookie_name)


	async def process_cookie_request(
		self,
		request,
		client_id: str,
		grant_type: str,
		code: str,
		redirect_uri: typing.Optional[str]
	) -> typing.Tuple[
		typing.Mapping[str, typing.Any],
		str,
		typing.Mapping[str, typing.Any],
	]:
		client_svc = self.App.get_service("seacatauth.ClientService")

		session = await self.CookieService.get_session_by_authorization_code(
			request,
			client_id=client_id,
			grant_type=grant_type,
			code=code,
		)

		if session.is_algorithmic():
			cookie_value = self.SessionService.Algorithmic.serialize(session)
			cookie_valid_until = self.SessionService.AnonymousExpiration
		else:
			cookie_value, cookie_valid_until = await self._create_cookie_token(session)
			await self.refresh_session(
				session,
				valid_until=cookie_valid_until,
				delete_after=cookie_valid_until,
			)

		client = await client_svc.get(client_id)

		if client.get("cookie_domain") not in (None, ""):
			domain = client["cookie_domain"]
		else:
			domain = self.RootCookieDomain

		cookie = {
			"value": cookie_value,
			"max_age": None,
			"domain": domain
		}

		# Determine the destination URI
		if not redirect_uri:
			# Fallback to client URI or Auth UI
			redirect_uri = client.get("client_uri") or self.AuthWebUiBaseUrl.rstrip("/")
		# TODO: Optionally validate the URI against client["redirect_uris"]
		#   and check if it is the same as in the authorization request

		# Trigger webhook and set custom client response headers
		try:
			data = await self._fetch_webhook_data(client, session)
			headers = data.get("response_headers", {})
		except exceptions.ClientResponseError as e:
			AuditLogger.error("Cookie request denied: Webhook error", struct_data={
				"cid": session.Credentials.Id,
				"sid": session.Id,
				"client_id": session.OAuth2.ClientId,
				"from_ip": AccessIps.get(),
				"redirect_uri": redirect_uri
			})
			raise InvalidRequest() from e

		AuditLogger.log(asab.LOG_NOTICE, "Cookie request granted", struct_data={
			"cid": session.Credentials.Id,
			"sid": session.Id,
			"client_id": session.OAuth2.ClientId,
			"from_ip": AccessIps.get(),
			"redirect_uri": redirect_uri
		})

		return cookie, redirect_uri, headers


	async def get_session_by_authorization_code(self, client_id: str, grant_type: str, code: str):
		if grant_type != "authorization_code":
			AuditLogger.log(
				asab.LOG_NOTICE,
				"Cookie request denied: Unsupported grant type.",
				struct_data={
					"client_id": client_id,
					"access_ips": AccessIps.get(),
					"grant_type": grant_type,
				}
			)
			raise UnsupportedGrantType(grant_type)

		try:
			session = await self.OpenIdConnectService.get_session_by_authorization_code(code)
		except exceptions.SessionNotFoundError:
			AuditLogger.log(
				asab.LOG_NOTICE,
				"Cookie request denied: Invalid or expired authorization code",
				struct_data={
					"client_id": client_id,
					"access_ips": AccessIps.get(),
				}
			)
			raise InvalidGrant()

		if client_id != session.OAuth2.ClientId:
			AuditLogger.log(
				asab.LOG_NOTICE,
				"Cookie request denied: Invalid client.",
				struct_data={
					"client_id": client_id,
					"access_ips": AccessIps.get(),
				}
			)
			raise InvalidClient(client_id)

		return session


	async def create_cookie(self, request, session: SessionAdapter) -> typing.Tuple[str, float]:
		# Establish and propagate track ID
		try:
			session = await self._set_track_id(request, session)
		except ValueError as e:
			AuditLogger.error(
				"Token request denied: Failed to produce session track ID",
				struct_data={
					"from_ip": AccessIps.get(),
					"cid": session.Credentials.Id,
					"client_id": session.OAuth2.ClientId,
				}
			)
			raise e


	async def _set_track_id(self, request, session: SessionAdapter) -> typing.Tuple[str, float]:
		# Set track ID if not set yet
		if session.TrackId is None:
			session = await self.SessionService.inherit_track_id_from_root(session)
		if session.TrackId is None:
			# Obtain the old session by request cookie or access token
			try:
				old_session = await self.get_session_by_request_cookie(
					request, session.OAuth2.ClientId)
			except exceptions.SessionNotFoundError:
				old_session = None
			except exceptions.NoCookieError:
				old_session = None

			token_value = generic.get_bearer_token_value(request)
			if old_session is None and token_value is not None:
				try:
					old_session = await self.OpenIdConnectService.get_session_by_access_token(token_value)
				except exceptions.SessionNotFoundError:
					old_session = None
			try:
				session = await self.SessionService.inherit_or_generate_new_track_id(session, old_session)
			except ValueError as e:
				L.error("Failed to produce session track ID")
				raise e
		return session


	async def _create_cookie_token(self, session: SessionAdapter) -> typing.Tuple[str, float]:
		"""
		Create cookie token

		@param session: Target session
		@return: Base64-encoded token and its expiration
		"""
		client_svc = self.App.get_service("seacatauth.ClientService")
		client = await client_svc.get(session.OAuth2.ClientId)
		expires_in = client.get("session_expiration") or CookieToken.Expiration
		raw_value, valid_until = await self.TokenService.create(
			token_length=CookieToken.ByteLength,
			token_type=CookieToken.TokenType,
			session_id=session.SessionId,
			expiration=expires_in,
			is_session_algorithmic=session.is_algorithmic(),
		)
		return base64.urlsafe_b64encode(raw_value).decode("ascii"), valid_until


	async def refresh_session(
		self,
		session: SessionAdapter,
		valid_until: typing.Optional[datetime.datetime] = None,
		delete_after: typing.Optional[datetime.datetime] = None,
	):
		"""
		Update/rebuild the session according to its authorization parameters
		"""
		# Get parent session
		root_session = await self.SessionService.get(session.Session.ParentSessionId)

		# Exclude critical resource grants from impersonated sessions
		if root_session.Authentication.ImpersonatorSessionId is not None:
			exclude_resources = {"authz:superuser", "authz:impersonate"}
		else:
			exclude_resources = set()

		# Authorize tenant
		authz = await build_credentials_authz(
			self.TenantService, self.RoleService, root_session.Credentials.Id,
			tenants=None,
			exclude_resources=exclude_resources
		)
		authorized_tenant = await self.get_accessible_tenant_from_scope(
			session.OAuth2.Scope, root_session.Credentials.Id,
			has_access_to_all_tenants=self.RBACService.can_access_all_tenants(authz)
		)

		session_builders = await self.SessionService.build_client_session(
			root_session,
			client_id=session.OAuth2.ClientId,
			scope=session.OAuth2.Scope,
			tenants=[authorized_tenant] if authorized_tenant else None,
			nonce=session.OAuth2.Nonce,
			redirect_uri=session.OAuth2.RedirectUri,
		)

		if valid_until:
			session_builders.append(((SessionAdapter.FN.Session.Expiration, valid_until),))

		if delete_after:
			session_builders.append(((SessionAdapter.FN.Session.DeleteAfter, delete_after),))

		session = await self.SessionService.update_session(session.SessionId, session_builders)

		return session


	async def _fetch_webhook_data(self, client, session):
		"""
		Make a webhook request and return the response body.
		The response should match the following schema:
		```json
		{
			"type": "object",
			"properties": {
				"response_headers": {
					"type": "object",
					"description": "HTTP headers and their values that will be added to the response."
				}
			}
		}
		```
		"""
		cookie_webhook_uri = client.get("cookie_webhook_uri")
		if cookie_webhook_uri is None:
			return None
		async with aiohttp.ClientSession() as http_session:
			# TODO: Better serialization
			userinfo = await self.OpenIdConnectService.build_userinfo(session)
			data = asab.web.rest.json.JSONDumper(pretty=False)(userinfo)
			async with http_session.put(cookie_webhook_uri, data=data, headers={
				"Content-Type": "application/json"}) as resp:
				if resp.status != 200:
					text = await resp.text()
					raise exceptions.ClientResponseError(resp.status, text)
				return await resp.json()
