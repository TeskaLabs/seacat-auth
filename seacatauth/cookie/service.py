import base64
import datetime
import hashlib
import re
import logging
import secrets

import asab
import asab.storage

from ..session import SessionAdapter
from ..session import (
	credentials_session_builder,
	authz_session_builder,
	cookie_session_builder
)
from ..openidconnect.session import oauth2_session_builder


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
			"(^{cookie}=[^;]*; ?|; ?{cookie}=[^;]*|^{cookie}=[^;]*)".format(cookie=self.CookieName)
		)
		self.CookieSecure = asab.Config.getboolean("seacatauth:cookie", "secure")
		self.RootCookieDomain = asab.Config.get("seacatauth:cookie", "domain") or None
		if self.RootCookieDomain is not None:
			self.RootCookieDomain = self._validate_cookie_domain(self.RootCookieDomain)

		self.AuthWebUiBaseUrl = asab.Config.get("general", "auth_webui_base_url")


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


	@staticmethod
	def _validate_cookie_domain(domain):
		if not domain.isascii():
			raise ValueError("Cookie domain can contain only ASCII characters.")
		domain = domain.lstrip(".")
		return domain or None


	def _get_session_cookie_id(self, request, client_id=None):
		"""
		Get Seacat cookie value from request header
		"""
		cookie = request.cookies.get(self.get_cookie_name(client_id))
		if cookie is None:
			return None
		try:
			session_cookie_id = base64.urlsafe_b64decode(cookie.encode("ascii"))
		except ValueError:
			L.warning("Cookie value is not base64", struct_data={"sci": cookie})
			return None
		return session_cookie_id


	async def get_session_by_sci(self, request, client_id=None):
		"""
		Find session by the combination of SCI (cookie ID) and client ID

		To search for root session, keep client_id=None.
		Root sessions have no client_id attribute, which MongoDB matches as None.
		"""
		session_cookie_id = self._get_session_cookie_id(request, client_id)
		if session_cookie_id is None:
			return None

		try:
			session = await self.SessionService.get_by({SessionAdapter.FN.Cookie.Id: session_cookie_id})
		except KeyError:
			L.info("Session not found.", struct_data={"sci": session_cookie_id})
			return None
		except ValueError:
			L.warning("Error retrieving session.", exc_info=True, struct_data={"sci": session_cookie_id})
			return None

		return session


	def get_cookie_domain(self, cookie_domain_id=None):
		if cookie_domain_id is not None:
			cookie_domain = self.ApplicationCookies.get(cookie_domain_id, {}).get("domain")
			if cookie_domain is None:
				L.error("Unknown cookie domain ID", struct_data={"domain_id": cookie_domain_id})
				raise KeyError("Unknown domain_id: {}".format(cookie_domain_id))
			return cookie_domain
		else:
			return self.RootCookieDomain


	async def get_session_by_authorization_code(self, code):
		oidc_svc = self.App.get_service("seacatauth.OpenIdConnectService")
		try:
			session_id = await oidc_svc.pop_session_id_by_authorization_code(code)
		except KeyError:
			L.warning("Authorization code not found", struct_data={"code": code})
			return None

		# Get the session
		try:
			session = await self.SessionService.get(session_id)
		except KeyError:
			L.error("Session not found", struct_data={"sid": session_id})
			return None

		return session


	async def create_cookie_client_session(self, root_session, client_id, scope, tenants, requested_expiration):
		"""
		Create a new cookie-based session

		Cookie-based sessions are uniquely identified by the combination of Cookie ID (SCI) and Client ID
		and do not have any Access Token.
		"""
		# Check if the Client exists
		client_svc = self.App.get_service("seacatauth.ClientService")
		try:
			await client_svc.get(client_id)
		except KeyError:
			raise KeyError("Client '{}' not found".format(client_id))

		# Check if session with the same cookie+client_id exists
		# If so, delete it
		try:
			session = await self.SessionService.get_by({
				SessionAdapter.FN.Cookie.Id: base64.urlsafe_b64decode(root_session.Cookie.Id.encode("ascii")),
				SessionAdapter.FN.OAuth2.ClientId: client_id,
			})
			await self.SessionService.delete(session.SessionId)
		except KeyError:
			pass

		# Build the session
		session_builders = [
			await credentials_session_builder(self.CredentialsService, root_session.Credentials.Id, scope),
			await authz_session_builder(
				tenant_service=self.TenantService,
				role_service=self.RoleService,
				credentials_id=root_session.Credentials.Id,
				tenants=tenants,
			),
			cookie_session_builder(),
		]

		if "profile" in scope or "userinfo:authn" in scope or "userinfo:*" in scope:
			session_builders.append([
				(SessionAdapter.FN.Authentication.LoginDescriptor, root_session.Authentication.LoginDescriptor),
				(SessionAdapter.FN.Authentication.ExternalLoginOptions, root_session.Authentication.ExternalLoginOptions),
				(SessionAdapter.FN.Authentication.AvailableFactors, root_session.Authentication.AvailableFactors),
			])

		if root_session.TrackId is not None:
			session_builders.append(((SessionAdapter.FN.Session.TrackId, root_session.TrackId),))
		# Otherwise keep the session without tracking ID for now

		oauth2_data = {
			"scope": scope,
			"client_id": client_id,
		}
		session_builders.append(oauth2_session_builder(oauth2_data))

		session = await self.SessionService.create_session(
			session_type="cookie",
			parent_session_id=root_session.SessionId,
			expiration=requested_expiration,
			session_builders=session_builders,
		)

		return session
