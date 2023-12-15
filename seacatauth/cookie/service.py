import base64
import datetime
import hashlib
import re
import logging

import asab
import asab.storage
import asab.exceptions
import jwcrypto.jws

from .. import exceptions
from ..session import SessionAdapter
from ..session.adapter import CookieData
from ..session import (
	credentials_session_builder,
	authz_session_builder,
	cookie_session_builder
)
from ..openidconnect.session import oauth2_session_builder
from .. import AuditLogger

#

L = logging.getLogger(__name__)

#


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
		# First try interpreting the token as an algorithmic session
		if "." in cookie_value:
			try:
				return await self.SessionService.Algorithmic.deserialize(cookie_value)
			except asab.exceptions.NotAuthenticatedError as e:
				# The JWToken is invalid or expired
				raise exceptions.SessionNotFoundError(
					"Invalid algorithmic session token", query={"cookie_value": cookie_value}) from e
			except jwcrypto.jws.InvalidJWSObject:
				# Not a JWT token
				pass

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


	async def get_session_by_authorization_code(self, code):
		return await self.OpenIdConnectService.pop_session_by_authorization_code(code)


	async def create_cookie_client_session(
		self, root_session, client_id, scope,
		nonce=None,
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

		# Make sure dangerous resources are removed from impersonated sessions
		if root_session.Authentication.ImpersonatorSessionId is not None:
			exclude_resources = {"authz:superuser", "authz:impersonate"}
		else:
			exclude_resources = None

		# Build the session
		session_builders = [
			await credentials_session_builder(self.CredentialsService, root_session.Credentials.Id, scope),
			await authz_session_builder(
				tenant_service=self.TenantService,
				role_service=self.RoleService,
				credentials_id=root_session.Credentials.Id,
				tenants=tenants,
				exclude_resources=exclude_resources,
			),
			cookie_session_builder(),
		]

		if "batman" in scope:
			batman_service = self.OpenIdConnectService.App.get_service("seacatauth.BatmanService")
			password = batman_service.generate_password(root_session.Credentials.Id)
			username = root_session.Credentials.Username
			basic_auth = base64.b64encode("{}:{}".format(username, password).encode("ascii"))
			session_builders.append([
				(SessionAdapter.FN.Batman.Token, basic_auth),
			])

		if "profile" in scope or "userinfo:authn" in scope or "userinfo:*" in scope:
			session_builders.append([
				(SessionAdapter.FN.Authentication.LoginDescriptor, root_session.Authentication.LoginDescriptor),
				(SessionAdapter.FN.Authentication.LoginFactors, root_session.Authentication.LoginFactors),
				(SessionAdapter.FN.Authentication.ExternalLoginOptions, root_session.Authentication.ExternalLoginOptions),
				(SessionAdapter.FN.Authentication.AvailableFactors, root_session.Authentication.AvailableFactors),
			])

		if root_session.TrackId is not None:
			session_builders.append(((SessionAdapter.FN.Session.TrackId, root_session.TrackId),))

		# Transfer impersonation data
		if root_session.Authentication.ImpersonatorSessionId is not None:
			session_builders.append((
				(
					SessionAdapter.FN.Authentication.ImpersonatorSessionId,
					root_session.Authentication.ImpersonatorSessionId
				),
				(
					SessionAdapter.FN.Authentication.ImpersonatorCredentialsId,
					root_session.Authentication.ImpersonatorCredentialsId
				),
			))

		session_builders.append(oauth2_session_builder(client_id, scope, nonce))

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
			scope=scope)

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
