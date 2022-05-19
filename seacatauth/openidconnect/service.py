import datetime
import json
import re
import base64
import secrets
import logging

import asab

import aiohttp.web
import urllib.parse
import jwcrypto.jwt

from ..session import SessionAdapter
from ..session import (
	credentials_session_builder,
	authz_session_builder,
	cookie_session_builder,
	login_descriptor_session_builder,
)
from .session import oauth2_session_builder

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
	AuthorizationCodeCollection = "ac"


	def __init__(self, app, service_name="seacatauth.OpenIdConnectService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.AuditService = app.get_service("seacatauth.AuditService")

		self.BearerRealm = asab.Config.get("openidconnect", "bearer_realm")
		self.Issuer = asab.Config.get("openidconnect", "issuer", fallback=None)
		if self.Issuer is None:
			fragments = urllib.parse.urlparse(asab.Config.get("general", "auth_webui_base_url"))
			L.warning("OAuth2 issuer not specified. Assuming '{}'".format(fragments.netloc))
			self.Issuer = fragments.netloc

		self.AuthorizationCodeTimeout = datetime.timedelta(
			seconds=asab.Config.getseconds("openidconnect", "auth_code_timeout")
		)

		self.App.PubSub.subscribe("Application.tick/60!", self._on_tick)


	async def _on_tick(self, event_name):
		await self.delete_expired_authorization_codes()


	async def generate_authorization_code(self, session_id):
		code = secrets.token_urlsafe(36)
		upsertor = self.StorageService.upsertor(self.AuthorizationCodeCollection, code)

		upsertor.set("sid", session_id)
		upsertor.set("exp", datetime.datetime.utcnow() + self.AuthorizationCodeTimeout)

		await upsertor.execute()

		return code


	async def delete_expired_authorization_codes(self):
		collection = self.StorageService.Database[self.AuthorizationCodeCollection]

		query_filter = {"exp": {"$lt": datetime.datetime.utcnow()}}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.info("Expired login sessions deleted", struct_data={
				"count": result.deleted_count
			})


	async def pop_session_id_by_authorization_code(self, code):
		collection = self.StorageService.Database[self.AuthorizationCodeCollection]
		data = await collection.find_one_and_delete(filter={"_id": code})
		if data is None:
			raise KeyError("Authorization code not found")

		session_id = data["sid"]
		exp = data["exp"]
		if exp is None or exp < datetime.datetime.utcnow():
			raise KeyError("Authorization code expired")

		return session_id


	async def get_session_by_bearer_token(self, bearer_token: str):
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
			session = await self.SessionService.get_by(SessionAdapter.FN.OAuth2.AccessToken, access_token)
		except KeyError:
			return None

		return session


	async def get_session_from_id_token(self, bearer_token: str):
		# Extract the access token
		token_value = self.AuthorizationHeaderRg.match(bearer_token)
		if token_value is None:
			L.warning("Access Token is invalid")
			return None

		id_token = token_value.group(1)
		# Create the session
		id_info = jwcrypto.jwt.JWT(jwt=id_token)
		payload = id_info.token.objects.get("payload")
		data_dict = json.loads(payload)

		session = SessionAdapter.from_id_token(self.SessionService, data_dict)

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


	async def create_oidc_session(self, root_session, client_id, scope, requested_expiration=None):
		# TODO: Choose builders based on scope
		session_builders = [
			await credentials_session_builder(self.CredentialsService, root_session.Credentials.Id),
			await authz_session_builder(
				tenant_service=self.TenantService,
				role_service=self.RoleService,
				credentials_id=root_session.Credentials.Id
			),
			login_descriptor_session_builder(root_session.Authentication.LoginDescriptor),
			cookie_session_builder(),
		]

		# TODO: if 'openid' in scope
		oauth2_data = {
			"scope": scope,
			"client_id": client_id,
		}
		session_builders.append(oauth2_session_builder(oauth2_data))
		session = await self.SessionService.create_session(
			session_type="openidconnect",
			parent_session=root_session,
			expiration=requested_expiration,
			session_builders=session_builders,
		)

		return session


	async def build_userinfo(self, session, tenant=None):
		userinfo = {
			"result": "OK",
			"iss": self.Issuer,
			"sub": session.Credentials.Id,  # The sub (subject) Claim MUST always be returned in the UserInfo Response.
			"exp": session.Session.Expiration,
			"iat": datetime.datetime.utcnow(),
		}

		if session.OAuth2.ClientId is not None:
			userinfo["aud"] = session.OAuth2.ClientId
			userinfo["azp"] = session.OAuth2.ClientId

		if session.Credentials.Username is not None:
			userinfo["preferred_username"] = session.Credentials.Username

		if session.Credentials.Email is not None:
			userinfo["email"] = session.Credentials.Email

		if session.Credentials.Phone is not None:
			userinfo["phone_number"] = session.Credentials.Phone

		if session.Credentials.ModifiedAt is not None:
			userinfo["updated_at"] = session.Credentials.ModifiedAt

		if session.Authentication.TOTPSet is not None:
			userinfo["totp_set"] = session.Authentication.TOTPSet

		if session.Authentication.AvailableFactors is not None:
			userinfo["available_factors"] = session.Authentication.AvailableFactors

		if session.Authentication.LoginDescriptor is not None:
			userinfo["ldid"] = session.Authentication.LoginDescriptor["id"]
			userinfo["factors"] = [
				factor["type"]
				for factor
				in session.Authentication.LoginDescriptor["factors"]
			]

		# List enabled external login providers
		if session.Authentication.ExternalLoginOptions is not None:
			userinfo["external_login_enabled"] = [
				account_type
				for account_type, account_id in session.Authentication.ExternalLoginOptions.items()
				if len(account_id) > 0
			]

		if session.Authorization.Authz is not None:
			userinfo["authz"] = session.Authorization.Authz

		if session.Authorization.Authz is not None:
			# Include the list of ALL the user's tenants (excluding "*")
			tenants = [t for t in session.Authorization.Authz.keys() if t != "*"]
			if len(tenants) > 0:
				userinfo["tenants"] = tenants

		if session.Authorization.Roles is not None:
			userinfo["roles"] = session.Authorization.Roles

		if session.Authorization.Resources is not None:
			userinfo["resources"] = session.Authorization.Resources

		if session.Authorization.Tenants is not None:
			userinfo["tenants"] = session.Authorization.Tenants

		# TODO: Last password change

		# Get last successful and failed login times
		# TODO: Store last login in session
		try:
			last_login = await self.AuditService.get_last_logins(session.Credentials.Id)
		except Exception as e:
			last_login = None
			L.warning("Could not fetch last logins: {}".format(e))

		if last_login is not None:
			if "fat" in last_login:
				userinfo["last_failed_login"] = last_login["fat"]
			if "sat" in last_login:
				userinfo["last_successful_login"] = last_login["sat"]

		# If tenant is missing or unknown, consider only global roles and resources
		if tenant not in session.Authorization.Authz:
			L.warning("Request for unknown tenant '{}', defaulting to '*'.".format(tenant))
			tenant = "*"

		# Include "roles" and "resources" sections, with items relevant to query_tenant
		session_roles = session.Authorization.Authz.get(tenant)
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
				"Tenant '{}' not found in session.Authorization.authz.".format(tenant),
				struct_data={
					"sid": session.SessionId,
					"cid": session.Credentials.Id,
					"authz": session.Authorization.Authz.keys()
				}
			)

		return userinfo
