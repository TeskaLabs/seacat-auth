import datetime
import json
import os.path
import base64
import secrets
import logging
import uuid

import asab
import asab.web.rest

import aiohttp.web
import urllib.parse
import jwcrypto.jwt
import jwcrypto.jwk
import jwcrypto.jws

from ..generic import add_params_to_url_query
from ..session import SessionAdapter
from ..session import (
	credentials_session_builder,
	authz_session_builder,
	login_descriptor_session_builder,
	external_login_session_builder,
	available_factors_session_builder
)
from .session import oauth2_session_builder
from ..audit import AuditCode
from .. import exceptions
from . import pkce

from ..events import EventTypes

#

L = logging.getLogger(__name__)

#

# TODO: Use JWA algorithms?


class OpenIdConnectService(asab.Service):

	# Bearer token Regex is based on RFC 6750
	# The OAuth 2.0 Authorization Framework: Bearer Token Usage
	# Chapter 2.1. Authorization Request Header Field
	AuthorizationCodeCollection = "ac"
	AuthorizePath = "/openidconnect/authorize"

	def __init__(self, app, service_name="seacatauth.OpenIdConnectService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.ClientService = app.get_service("seacatauth.ClientService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.RBACService = app.get_service("seacatauth.RBACService")
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.AuditService = app.get_service("seacatauth.AuditService")
		self.PKCE = pkce.PKCE()  # TODO: Restructure. This is OAuth, but not OpenID Connect!

		self.BearerRealm = asab.Config.get("openidconnect", "bearer_realm")
		self.Issuer = asab.Config.get("openidconnect", "issuer", fallback=None)
		if self.Issuer is None:
			fragments = urllib.parse.urlparse(asab.Config.get("general", "auth_webui_base_url"))
			L.warning("OAuth2 issuer not specified. Assuming '{}'".format(fragments.netloc))
			self.Issuer = fragments.netloc

		self.AuthorizationCodeTimeout = datetime.timedelta(
			seconds=asab.Config.getseconds("openidconnect", "auth_code_timeout")
		)

		public_api_base_url = asab.Config.get("general", "public_api_base_url")
		if public_api_base_url.endswith("/"):
			self.PublicApiBaseUrl = public_api_base_url[:-1]
		else:
			self.PublicApiBaseUrl = public_api_base_url

		self.PrivateKey = self._load_private_key()

		self.JSONDumper = asab.web.rest.json.JSONDumper(pretty=False)

		app.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)


	async def _on_housekeeping(self, event_name):
		await self._delete_expired_authorization_codes()


	def _load_private_key(self):
		"""
		Load private key from file.
		If it does not exist, generate a new one and write to file.
		"""
		# TODO: Add encryption option
		# TODO: Multiple key support
		private_key_path = asab.Config.get("openidconnect", "private_key")
		if len(private_key_path) == 0:
			# Use config folder
			private_key_path = os.path.join(
				os.path.dirname(asab.Config.get("general", "config_file")),
				"private-key.pem"
			)
			L.log(
				asab.LOG_NOTICE,
				"OpenIDConnect private key file not specified. Defaulting to '{}'.".format(private_key_path)
			)

		if os.path.isfile(private_key_path):
			with open(private_key_path, "rb") as f:
				private_key = jwcrypto.jwk.JWK.from_pem(f.read())
		elif self.App.Provisioning:
			# Generate a new private key
			L.warning(
				"OpenIDConnect private key file does not exist. Generating a new one."
			)
			private_key = self._generate_private_key(private_key_path)
		else:
			raise FileNotFoundError(
				"Private key file '{}' does not exist. "
				"Run the app in provisioning mode to generate a new private key.".format(private_key_path)
			)

		assert private_key.key_type == "EC"
		assert private_key.key_curve == "P-256"
		return private_key


	def _generate_private_key(self, private_key_path):
		assert not os.path.isfile(private_key_path)

		import cryptography.hazmat.backends
		import cryptography.hazmat.primitives.serialization
		import cryptography.hazmat.primitives.asymmetric.ec
		import cryptography.hazmat.primitives.ciphers.algorithms
		_private_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
			cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
			cryptography.hazmat.backends.default_backend()
		)
		# Serialize into PEM
		private_pem = _private_key.private_bytes(
			encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
			format=cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
			encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption()
		)
		with open(private_key_path, "wb") as f:
			f.write(private_pem)
		L.log(
			asab.LOG_NOTICE,
			"New private key written to '{}'.".format(private_key_path)
		)
		private_key = jwcrypto.jwk.JWK.from_pem(private_pem)
		return private_key


	async def generate_authorization_code(self, session_id):
		code = secrets.token_urlsafe(36)
		upsertor = self.StorageService.upsertor(self.AuthorizationCodeCollection, code)

		upsertor.set("sid", session_id)
		upsertor.set("exp", datetime.datetime.now(datetime.timezone.utc) + self.AuthorizationCodeTimeout)

		await upsertor.execute(event_type=EventTypes.OPENID_AUTH_CODE_GENERATED)

		return code


	async def _delete_expired_authorization_codes(self):
		collection = self.StorageService.Database[self.AuthorizationCodeCollection]

		query_filter = {"exp": {"$lt": datetime.datetime.now(datetime.timezone.utc)}}
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
		if exp is None or exp < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("Authorization code expired")

		return session_id


	async def get_session_by_access_token(self, token_value):
		# Decode the access token
		try:
			access_token = base64.urlsafe_b64decode(token_value)
		except ValueError:
			L.info("Access token is not base64: '{}'".format(token_value))
			return None

		# Locate the session
		try:
			session = await self.SessionService.get_by(SessionAdapter.FN.OAuth2.AccessToken, access_token)
		except KeyError:
			L.info("Session not found by access token: {}".format(access_token))
			return None

		return session


	async def get_session_by_id_token(self, token_value):
		try:
			token = jwcrypto.jwt.JWT(jwt=token_value, key=self.PrivateKey)
		except jwcrypto.jwt.JWTExpired:
			L.warning("ID token expired")
			return None
		except jwcrypto.jws.InvalidJWSSignature:
			L.warning("Invalid ID token signature")
			return None

		try:
			data_dict = json.loads(token.claims)
			session_id = data_dict["sid"]
		except ValueError:
			L.warning("Cannot read ID token claims")
			return None
		except KeyError:
			L.warning("ID token claims do not contain 'sid'")
			return None

		try:
			session = await self.SessionService.get(session_id)
		except ValueError:
			L.warning("Session not found")
			return None

		return session


	def refresh_token(self, refresh_token, client_id, client_secret, scope):
		# TODO: this is not implemented
		L.error("refresh_token is not implemented", struct_data=[refresh_token, client_id, client_secret, scope])
		raise aiohttp.web.HTTPNotImplemented()


	def check_access_token(self, bearer_token):
		# TODO: this is not implemented
		L.error("check_access_token is not implemented", struct_data={"bearer": bearer_token})
		raise aiohttp.web.HTTPNotImplemented()


	async def create_oidc_session(
		self, root_session, client_id, scope,
		tenants=None,
		requested_expiration=None,
		code_challenge: str = None,
		code_challenge_method: str = None
	):
		# TODO: Choose builders based on scope
		# Make sure dangerous resources are removed from impersonated sessions
		if root_session.Authentication.ImpersonatorSessionId is not None:
			exclude_resources = {"authz:superuser", "authz:impersonate"}
		else:
			exclude_resources = set()

		session_builders = [
			await credentials_session_builder(self.CredentialsService, root_session.Credentials.Id, scope),
			await authz_session_builder(
				tenant_service=self.TenantService,
				role_service=self.RoleService,
				credentials_id=root_session.Credentials.Id,
				tenants=tenants,
				exclude_resources=exclude_resources,
			)
		]

		if code_challenge is not None:
			session_builders.append((
				(SessionAdapter.FN.OAuth2.PKCE, {"challenge": code_challenge, "method": code_challenge_method}),
			))

		if "profile" in scope or "userinfo:authn" in scope or "userinfo:*" in scope:
			session_builders.append([
				(SessionAdapter.FN.Authentication.LoginDescriptor, root_session.Authentication.LoginDescriptor),
				(SessionAdapter.FN.Authentication.AvailableFactors, root_session.Authentication.AvailableFactors),
				(
					SessionAdapter.FN.Authentication.ExternalLoginOptions,
					root_session.Authentication.ExternalLoginOptions
				),
			])

		# TODO: if 'openid' in scope
		oauth2_data = {
			"scope": scope,
			"client_id": client_id,
		}
		session_builders.append(oauth2_session_builder(oauth2_data))

		# Obtain Track ID if there is any in the root session
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

		session = await self.SessionService.create_session(
			session_type="openidconnect",
			parent_session_id=root_session.SessionId,
			expiration=requested_expiration,
			session_builders=session_builders,
		)

		return session


	async def create_anonymous_oidc_session(
		self, anonymous_cid, client_id, scope,
		login_descriptor=None,
		track_id=None,
		root_session_id=None,
		tenants=None,
		requested_expiration=None,
		code_challenge: str = None,
		code_challenge_method: str = None,
		from_info=None,
	):
		ext_login_svc = self.App.get_service("seacatauth.ExternalLoginService")
		session_builders = [
			((SessionAdapter.FN.Authentication.IsAnonymous, True),),
			await credentials_session_builder(self.CredentialsService, anonymous_cid, scope),
			await authz_session_builder(
				tenant_service=self.TenantService,
				role_service=self.RoleService,
				credentials_id=anonymous_cid,
				tenants=tenants,
			)
		]

		if code_challenge is not None:
			session_builders.append((
				(SessionAdapter.FN.OAuth2.PKCE, {"challenge": code_challenge, "method": code_challenge_method}),
			))

		if "profile" in scope or "userinfo:authn" in scope or "userinfo:*" in scope:
			authn_service = self.App.get_service("seacatauth.AuthenticationService")
			session_builders.append(login_descriptor_session_builder(login_descriptor))
			session_builders.append(await external_login_session_builder(ext_login_svc, anonymous_cid))
			# TODO: Get factors from root_session?
			session_builders.append(await available_factors_session_builder(authn_service, anonymous_cid))

		# TODO: if 'openid' in scope
		oauth2_data = {
			"scope": scope,
			"client_id": client_id,
		}
		session_builders.append(oauth2_session_builder(oauth2_data))

		# Obtain Track ID if there is any in the root session
		if track_id is not None:
			session_builders.append(((SessionAdapter.FN.Session.TrackId, track_id),))

		session = await self.SessionService.create_session(
			session_type="openidconnect",
			parent_session_id=root_session_id,
			expiration=requested_expiration,
			session_builders=session_builders,
		)

		L.log(asab.LOG_NOTICE, "Anonymous session created.", struct_data={
			"cid": anonymous_cid,
			"client_id": client_id,
			"sid": str(session.Session.Id),
			"fi": from_info})

		# Add an audit entry
		await self.AuditService.append(AuditCode.ANONYMOUS_SESSION_CREATED, {
			"cid": anonymous_cid,
			"client_id": client_id,
			"sid": str(session.Session.Id),
			"fi": from_info})

		return session


	async def build_userinfo(self, session):
		# TODO: Session object should only serve as a cache
		#   After the cache has expired, update session object with fresh credential, authn and authz data
		#   and rebuild the userinfo

		otp_service = self.App.get_service("seacatauth.OTPService")

		userinfo = {
			"iss": self.Issuer,
			"sub": session.Credentials.Id,  # The sub (subject) Claim MUST always be returned in the UserInfo Response.
			"exp": session.Session.Expiration,
			"iat": session.CreatedAt,
			"sid": session.SessionId,
		}

		if session.Session.ParentSessionId is not None:
			userinfo["psid"] = session.Session.ParentSessionId

		if session.OAuth2.ClientId is not None:
			# aud indicates who is allowed to consume the token
			# azp indicates who is allowed to present it
			userinfo["aud"] = session.OAuth2.ClientId
			userinfo["azp"] = session.OAuth2.ClientId

		if session.OAuth2.Scope is not None:
			userinfo["scope"] = session.OAuth2.Scope

		if session.Credentials.Username is not None:
			userinfo["username"] = session.Credentials.Username
			userinfo["preferred_username"] = session.Credentials.Username  # BACK COMPAT, remove after 2023-01-31

		if session.Credentials.Email is not None:
			userinfo["email"] = session.Credentials.Email

		if session.Credentials.Phone is not None:
			userinfo["phone"] = session.Credentials.Phone
			userinfo["phone_number"] = session.Credentials.Phone   # BACK COMPAT, remove after 2023-01-31

		if session.Credentials.CustomData is not None:
			userinfo["custom"] = session.Credentials.CustomData

		if session.Credentials.ModifiedAt is not None:
			userinfo["updated_at"] = session.Credentials.ModifiedAt

		if session.Credentials.CreatedAt is not None:
			userinfo["created_at"] = session.Credentials.CreatedAt

		if session.Authentication.IsAnonymous:
			userinfo["anonymous"] = True

		if session.TrackId is not None:
			userinfo["track_id"] = uuid.UUID(bytes=session.TrackId)

		if session.Authentication.ImpersonatorSessionId:
			userinfo["impersonator_sid"] = session.Authentication.ImpersonatorSessionId
			userinfo["impersonator_cid"] = session.Authentication.ImpersonatorCredentialsId

		if await otp_service.has_activated_totp(session.Credentials.Id):
			userinfo["totp_set"] = True

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
			userinfo["resources"] = session.Authorization.Authz

		if session.Authorization.Tenants is not None:
			userinfo["tenants"] = session.Authorization.Tenants

		# TODO: Last password change

		# RFC 7519 states that the exp and iat claim values must be NumericDate values
		# Convert ALL datetimes to UTC timestamps for consistency
		for k, v in userinfo.items():
			if isinstance(v, datetime.datetime):
				userinfo[k] = int(v.timestamp())

		return userinfo


	async def build_id_token(self, session):
		"""
		Wrap authentication data and userinfo in a JWT token
		"""
		header = {
			"alg": "ES256",  # TODO: This should be mapped from key_type and key_curve
			"typ": "JWT",
			"kid": self.PrivateKey.key_id,
		}

		# TODO: ID token should always contain info about "what happened during authentication"
		#   User info is optional and its parts should be included (or not) based on SCOPE
		payload = await self.build_userinfo(session)

		token = jwcrypto.jwt.JWT(
			header=header,
			claims=self.JSONDumper(payload)
		)
		token.make_signed_token(self.PrivateKey)
		id_token = token.serialize()

		return id_token


	async def authorize_tenants_by_scope(self, scope, session, client_id):
		has_access_to_all_tenants = self.RBACService.has_resource_access(
			session.Authorization.Authz, tenant=None, requested_resources=["authz:superuser"]) \
			or self.RBACService.has_resource_access(
			session.Authorization.Authz, tenant=None, requested_resources=["authz:tenant:access"])
		try:
			tenants = await self.TenantService.get_tenants_by_scope(
				scope, session.Credentials.Id, has_access_to_all_tenants)
		except exceptions.TenantNotFoundError as e:
			L.error("Tenant not found", struct_data={"tenant": e.Tenant})
			await self.audit_authorize_error(
				client_id, "access_denied:tenant_not_found",
				credential_id=session.Credentials.Id,
				tenant=e.Tenant,
				scope=scope
			)
			raise exceptions.AccessDeniedError(subject=session.Credentials.Id)
		except exceptions.TenantAccessDeniedError as e:
			L.error("Tenant access denied", struct_data={"tenant": e.Tenant, "cid": session.Credentials.Id})
			await self.audit_authorize_error(
				client_id, "access_denied:unauthorized_tenant",
				credential_id=session.Credentials.Id,
				tenant=e.Tenant,
				scope=scope
			)
			raise exceptions.AccessDeniedError(subject=session.Credentials.Id)
		except exceptions.NoTenantsError:
			L.error("Tenant access denied", struct_data={"cid": session.Credentials.Id})
			await self.audit_authorize_error(
				client_id, "access_denied:user_has_no_tenant",
				credential_id=session.Credentials.Id,
				scope=scope
			)
			raise exceptions.AccessDeniedError(subject=session.Credentials.Id)

		return tenants


	async def audit_authorize_success(self, session):
		await self.AuditService.append(AuditCode.AUTHORIZE_SUCCESS, {
			"cid": session.Credentials.Id,
			"tenants": [t for t in session.Authorization.Authz if t != "*"],
			"client_id": session.OAuth2.ClientId,
			"scope": session.OAuth2.Scope,
		})


	async def audit_authorize_error(self, client_id, error, credential_id=None, **kwargs):
		d = {
			"client_id": client_id,
			"error": error,
			**kwargs
		}
		if credential_id is not None:
			d["cid"] = credential_id
		await self.AuditService.append(AuditCode.AUTHORIZE_ERROR, d)


	def build_authorize_uri(self, client_dict, **query_params):
		"""
		Check if the client has a registered OAuth Authorize URI. If not, use the default.
		Extend the URI with query parameters.
		"""
		authorize_uri = client_dict.get("authorize_uri")
		if authorize_uri is None:
			authorize_uri = "{}{}".format(self.PublicApiBaseUrl, self.AuthorizePath)
		return add_params_to_url_query(authorize_uri, **query_params)
