import base64
import datetime
import hashlib
import re
import logging
import typing
import asab
import asab.storage
import asab.exceptions

from .. import exceptions
from ..models import Session

from ..models.session import CookieData
from ..session.builders import cookie_session_builder
from .. import AuditLogger


L = logging.getLogger(__name__)


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
			session = await self.SessionService.get_by(Session.FN.Cookie.Id, cookie_value)
		except KeyError as e:
			raise exceptions.SessionNotFoundError(
				"Session not found", query={"cookie_value": cookie_value}) from e
		except ValueError as e:
			raise exceptions.SessionNotFoundError(
				"Error deserializing session", query={"cookie_value": cookie_value}) from e

		return session


	async def get_session_by_authorization_code(self, code):
		return await self.OpenIdConnectService.get_session_by_authorization_code(code)


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
			await client_svc.get_client(client_id)
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
		session_builders.append(cookie_session_builder())

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


	async def extend_session_expiration(self, session: Session, client: dict = None):
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
