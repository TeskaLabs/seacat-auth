import re
import time
import base64
import secrets
import logging

import asab

import aiohttp.web
import urllib.parse

from ..session import SessionAdapter

#

L = logging.getLogger(__name__)

#

# TODO: Use JWA algorithms?


class OpenIdConnectService(asab.Service):

	asab.Config.add_defaults(
		{
		}
	)

	# Bearer token Regex is based on RFC 6750
	# The OAuth 2.0 Authorization Framework: Bearer Token Usage
	# Chapter 2.1. Authorization Request Header Field
	AuthorizationHeaderRg = re.compile(r"^\s*Bearer ([A-Za-z0-9\-\.\+_~/=]*)")


	def __init__(self, app, service_name="seacatauth.OpenIdConnectService"):
		super().__init__(app, service_name)
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.AuditService = app.get_service("seacatauth.AuditService")

		self.BearerRealm = asab.Config.get("openidconnect", "bearer_realm")
		self.Issuer = asab.Config.get("openidconnect", "issuer", fallback=None)
		if self.Issuer is None:
			fragments = urllib.parse.urlparse(asab.Config.get("general", "auth_webui_base_url"))
			L.warning("OAuth2 issuer not specified. Assuming '{}'".format(fragments.netloc))
			self.Issuer = fragments.netloc

		# A map of authorization codes to sessions
		# TODO: Expiration of these
		self.AuthorizationCodes = {}
		self.AuthorizationCodeExpiration = 30  # seconds


	def generate_authotization_code(self, session_id):
		while True:
			code = secrets.token_urlsafe(36)
			if code in self.AuthorizationCodes:
				continue
			self.AuthorizationCodes[code] = (session_id, time.time() + self.AuthorizationCodeExpiration)
			return code


	def pop_session_id_by_authorization_code(self, code):
		session_id, exptime = self.AuthorizationCodes.pop(code, (None, None))
		if exptime is None or exptime < time.time():
			return None
		return session_id


	async def get_session_from_bearer_token(self, bearer_token: str):
		# Extract the access token
		am = self.AuthorizationHeaderRg.match(bearer_token)
		if am is None:
			L.warning("Access Token is invalid")
			return None

		# Decode the access token
		try:
			access_token = base64.urlsafe_b64decode(am.group(1))
		except ValueError:
			L.warning("Access Token is not base64: '{}'".format(am.group(1)))
			return None

		# Locate the session
		try:
			session = await self.SessionService.get_by(SessionAdapter.FNOAuth2AccessToken, access_token)
		except KeyError:
			L.warning("Access Token not found", struct_data={'at': access_token})
			return None

		return session


	async def get_session_from_authorization_header(self, request):
		"""
		Find session by token in the authorization header
		"""
		# Get authorization header
		authorization_bytes = request.headers.get(aiohttp.hdrs.AUTHORIZATION, None)
		if authorization_bytes is None:
			L.info("Access Token not provided in the header")
			return None

		return await self.get_session_from_bearer_token(authorization_bytes)

	def refresh_token(self, refresh_token, client_id, client_secret, scope):
		# TODO: this is not implemented
		L.error("refresh_token is not implemented", struct_data=[refresh_token, client_id, client_secret, scope])
		raise aiohttp.web.HTTPNotImplemented()

	def check_access_token(self, bearer_token):
		# TODO: this is not implemented
		L.error("check_access_token is not implemented", struct_data={"bearer": bearer_token})
		raise aiohttp.web.HTTPNotImplemented()

	async def build_userinfo(self, session, tenant=None):
		userinfo = {
			"result": "OK",
			"iss": self.Issuer,
			"sub": session.CredentialsId,  # The sub (subject) Claim MUST always be returned in the UserInfo Response.
		}

		try:
			credentials = await self.CredentialsService.get(session.CredentialsId, include=frozenset(["__totp"]))
		except KeyError:
			L.error("Credentials not found", struct_data={"cid": session.CredentialsId})
			return {"result": "CREDENTIALS-NOT-FOUND"}

		v = credentials.get("username")
		if v is not None:
			userinfo["preferred_username"] = v

		v = credentials.get("email")
		if v is not None:
			userinfo["email"] = v

		v = credentials.get("phone")
		if v is not None:
			userinfo["phone_number"] = v

		v = credentials.get("_m")
		if v is not None:
			userinfo["updated_at"] = v

		v = credentials.get("__totp")
		# TODO: Use OTPService or TOTPFactor to get this information
		if v is not None and len(v) > 0:
			userinfo["totp_set"] = True

		# TODO: last password change

		# Get last successful and failed login times
		try:
			last_login = await self.AuditService.get_last_logins(session.CredentialsId)
		except Exception as e:
			last_login = None
			L.warning("Could not fetch last logins: {}".format(e))

		if last_login is not None:
			if "fat" in last_login:
				userinfo["last_failed_login"] = last_login["fat"]
			if "sat" in last_login:
				userinfo["last_successful_login"] = last_login["sat"]

		userinfo["exp"] = "{}Z".format(session.Expiration.isoformat())

		userinfo["available_factors"] = session.AvailableFactors

		if session.LoginDescriptor is not None:
			userinfo["ldid"] = session.LoginDescriptor["id"]
			userinfo["factors"] = [
				factor["id"]
				for factor
				in session.LoginDescriptor["factors"]
			]

		# List enabled external login providers
		accounts = credentials.get("external_login")
		if accounts is not None:
			userinfo["external_login_enabled"] = [
				account_type
				for account_type, account_id in accounts.items()
				if len(account_id) > 0
			]

		if self.TenantService.is_enabled():
			# Include "tenants" section, list ALL of user's tenants (excluding "*")
			tenants = [t for t in session.Authz.keys() if t != "*"]
			if tenants is not None:
				userinfo["tenants"] = tenants

		# If tenant is missing or unknown, consider only global roles and resources
		if tenant not in session.Authz:
			L.warning("Request for unknown tenant '{}', defaulting to '*'.".format(tenant))
			tenant = "*"

		# Include "roles" and "resources" sections, with items relevant to query_tenant
		session_roles = session.Authz.get(tenant)
		if session_roles is not None:
			roles = []
			resources = set()
			for session_role, session_resources in session_roles.items():
				roles.append(session_role)
				resources.update(session_resources)
			if len(roles) > 0:
				userinfo["roles"] = roles
			if len(resources) > 0:
				userinfo["resources"] = list(resources)
		else:
			L.error(
				"Tenant '{}' not found in session.Authz.".format(tenant),
				struct_data={
					"sid": session.SessionId,
					"cid": session.CredentialsId,
					"authz": session.Authz.keys()
				}
			)

		return userinfo

