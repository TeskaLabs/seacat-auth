import base64
import http.cookies
import re
import urllib.parse

import aiohttp
import logging

import asab
import asab.storage

from ..session import SessionAdapter


#

L = logging.getLogger(__name__)

#


class CookieService(asab.Service):
	def __init__(self, app, service_name="seacatauth.CookieService"):
		super().__init__(app, service_name)
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.TenantService = app.get_service("seacatauth.TenantService")

		# Configure root cookie
		self.CookieName = asab.Config.get("seacatauth:cookie", "name")
		self.RootCookieDomain = self._validate_cookie_domain(
			asab.Config.get("seacatauth:cookie", "domain", fallback=None)
		)
		if self.RootCookieDomain is None:
			fragments = urllib.parse.urlparse(asab.Config.get("general", "auth_webui_base_url"))
			if fragments.netloc == "localhost":
				self.RootCookieDomain = fragments.netloc
			else:
				self.RootCookieDomain = ".{}".format(fragments.netloc)
			L.warning("""Cookie domain is not specified.
				Assuming your cookie domain is '{}' (inferred from Auth WebUI base URL).
				It is recommended to specify cookie domain explicitly in your Seacat Auth configuration file.
			""".replace("\t", "").format(self.RootCookieDomain))

		# Configure cookies for application domains
		# TODO: Allow different cookie name for each domain
		self.ApplicationCookies = {}
		self.ApplicationCookieDomains = set()
		section_pattern = re.compile(r"^seacatauth:cookie:([-_.0-9A-Za-z]+)$")
		for section_name in asab.Config.sections():
			match = section_pattern.match(section_name)
			if match is None:
				continue
			domain_id = match.group(1)
			section = asab.Config[section_name]

			redirect_uri = section.get("redirect_uri", asab.Config.get("general", "auth_webui_base_url"))
			domain = self._validate_cookie_domain(section.get("domain"))
			if domain is None:
				raise ValueError("Application cookie domain must be specified.")

			self.ApplicationCookies[domain_id] = {
				"redirect_uri": redirect_uri,
				"domain": domain
			}
			self.ApplicationCookieDomains.add(domain)


	@staticmethod
	def _validate_cookie_domain(domain):
		if domain in ("", None):
			L.warning("Cookie domain not specified or empty")
			return None
		if not domain.isascii():
			L.warning("Cookie domain can contain only ASCII characters.", struct_data={"domain": domain})
			return None
		return domain


	def _get_session_cookie_id(self, request):
		"""
		Get Seacat cookie value from request header
		"""
		raw_cookies = request.headers.get(aiohttp.hdrs.COOKIE)
		if raw_cookies is None:
			return None

		# Custom cookie parsing to prevent overwriting cookies that share the same name
		for cookie_string in raw_cookies.split(";"):
			# Check if cookie name matches
			split_cookie = http.cookies.SimpleCookie(cookie_string)
			cookie = split_cookie.get(self.CookieName)
			if cookie is None:
				continue

			# Split away prefix
			try:
				domain, session_cookie_id_encoded = cookie.value.split(":", 1)
			except ValueError:
				# Cookie has no domain prefix
				continue

			# Check if domain matches
			if domain == self.RootCookieDomain or domain in self.ApplicationCookieDomains:
				session_cookie_id = base64.urlsafe_b64decode(session_cookie_id_encoded)
				return session_cookie_id

		return None


	async def get_session_by_sci(self, request):
		session_cookie_id = self._get_session_cookie_id(request)
		if session_cookie_id is None:
			return None

		try:
			session = await self.SessionService.get_by(SessionAdapter.FN.Cookie.Id, session_cookie_id)
		except KeyError:
			L.info("Session not found", struct_data={"sci": session_cookie_id})
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
