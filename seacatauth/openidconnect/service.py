import datetime
import json
import base64
import secrets
import logging

import asab
import asab.web.rest
import asab.exceptions

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
	TokenPath = "/openidconnect/token"
	TokenRevokePath = "/openidconnect/token/revoke"
	UserInfoPath = "/openidconnect/userinfo"
	JwksPath = "/openidconnect/public_keys"
	EndSessionPath = "/openidconnect/logout"

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

		self.PublicApiBaseUrl = app.PublicOpenIdConnectApiUrl

		self.BearerRealm = asab.Config.get("openidconnect", "bearer_realm")

		# The Issuer value must be an URL, such that when "/.well-known/openid-configuration" is appended to it,
		# we obtain a valid URL containing the issuer's OpenID configuration metadata.
		# (https://www.rfc-editor.org/rfc/rfc8414#section-3)
		self.Issuer = asab.Config.get("openidconnect", "issuer", fallback=None)
		if self.Issuer is not None:
			parsed = urllib.parse.urlparse(self.Issuer)
			if parsed.scheme != "https" or parsed.query != "" or parsed.fragment != "":
				raise ValueError(
					"OpenID Connect issuer must be a URL that uses the 'https' scheme "
					"and has no query or fragment components.")
		else:
			# Default fallback option
			self.Issuer = self.PublicApiBaseUrl.rstrip("/")

		self.AuthorizationCodeTimeout = datetime.timedelta(
			seconds=asab.Config.getseconds("openidconnect", "auth_code_timeout")
		)

		self.DisableRedirectUriValidation = asab.Config.getboolean(
			"openidconnect", "_disable_redirect_uri_validation", fallback=False)
		if self.DisableRedirectUriValidation:
			# This is a dev-only option
			L.warning("Redirect URI validation in OpenID Authorize requests is disabled.")

		# TODO: Derive the private key
		self.PrivateKey = app.PrivateKey

		self.JSONDumper = asab.web.rest.json.JSONDumper(pretty=False)

		app.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)


	async def _on_housekeeping(self, event_name):
		await self._delete_expired_authorization_codes()


	async def generate_authorization_code(
		self,
		session: SessionAdapter,
		code_challenge: str = None,
		code_challenge_method: str = None
	):
		"""
		Generates a random authorization code and stores it as a temporary
		session identifier until the session is retrieved.
		"""
		# TODO: Store PKCE challenge here, not in the session object
		code = secrets.token_urlsafe(36)
		upsertor = self.StorageService.upsertor(self.AuthorizationCodeCollection, code)

		if session.is_algorithmic():
			algo_token = self.SessionService.Algorithmic.serialize(session)
			upsertor.set("alt", algo_token.encode("ascii"), encrypt=True)
			upsertor.set("client_id", session.OAuth2.ClientId)
			upsertor.set("scope", session.OAuth2.Scope)
		else:
			upsertor.set("sid", session.SessionId)

		if code_challenge:
			upsertor.set("cc", code_challenge)
			upsertor.set("ccm", code_challenge_method)

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


	async def pop_session_by_authorization_code(self, code, code_verifier: str = None):
		"""
		Retrieves session by its temporary authorization code.
		"""
		collection = self.StorageService.Database[self.AuthorizationCodeCollection]
		data = await collection.find_one_and_delete(filter={"_id": code})
		if data is None:
			raise KeyError("Authorization code not found.")

		exp = data["exp"]
		if exp is None or exp < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("Authorization code expired.")

		if "cc" in data:
			self.PKCE.evaluate_code_challenge(
				code_challenge_method=data["ccm"],
				code_challenge=data["cc"],
				code_verifier=code_verifier)

		if "sid" in data:
			return await self.SessionService.get(data["sid"])
		elif "alt" in data:
			algo_token = self.StorageService.aes_decrypt(data["alt"])
			return await self.SessionService.Algorithmic.deserialize(algo_token.decode("ascii"))
		else:
			L.error("Unexpected authorization code object.", struct_data=data)
			raise KeyError("Invalid authorization code.")


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
			L.error("Invalid ID token signature")
			return None

		try:
			data_dict = json.loads(token.claims)
			session_id = data_dict["sid"]
		except ValueError:
			L.error("Cannot read ID token claims")
			return None
		except KeyError:
			L.error("ID token claims do not contain 'sid'")
			return None

		try:
			session = await self.SessionService.get(session_id)
		except exceptions.SessionNotFoundError:
			L.error("Session associated with ID token not found", struct_data={"sid": session_id})
			return None

		return session


	def refresh_token(self, refresh_token, client_id, client_secret, scope):
		# TODO: this is not implemented
		L.error("refresh_token is not implemented", struct_data=[refresh_token, client_id, client_secret, scope])
		return aiohttp.web.HTTPNotImplemented()


	def check_access_token(self, bearer_token):
		# TODO: this is not implemented
		L.error("check_access_token is not implemented", struct_data={"bearer": bearer_token})
		return aiohttp.web.HTTPNotImplemented()


	async def create_oidc_session(
		self, root_session, client_id, scope,
		nonce=None,
		tenants=None,
		requested_expiration=None
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

		if "profile" in scope or "userinfo:authn" in scope or "userinfo:*" in scope:
			session_builders.append([
				(SessionAdapter.FN.Authentication.LoginDescriptor, root_session.Authentication.LoginDescriptor),
				(SessionAdapter.FN.Authentication.LoginFactors, root_session.Authentication.LoginFactors),
				(SessionAdapter.FN.Authentication.AvailableFactors, root_session.Authentication.AvailableFactors),
				(
					SessionAdapter.FN.Authentication.ExternalLoginOptions,
					root_session.Authentication.ExternalLoginOptions
				),
			])

		if "batman" in scope:
			batman_service = self.App.get_service("seacatauth.BatmanService")
			password = batman_service.generate_password(root_session.Credentials.Id)
			username = root_session.Credentials.Username
			basic_auth = base64.b64encode("{}:{}".format(username, password).encode("ascii"))
			session_builders.append([
				(SessionAdapter.FN.Batman.Token, basic_auth),
			])

		session_builders.append(oauth2_session_builder(client_id, scope, nonce))

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
		self, anonymous_cid: str, client_dict: dict, scope: list,
		track_id: bytes = None,
		tenants: list = None,
		from_info=None
	):
		session = await self.SessionService.Algorithmic.create_anonymous_session(
			created_at=datetime.datetime.now(datetime.timezone.utc),
			track_id=track_id,
			client_dict=client_dict,
			scope=scope)

		session.OAuth2.AccessToken = self.SessionService.Algorithmic.serialize(session)

		L.log(asab.LOG_NOTICE, "Anonymous session created.", struct_data={
			"cid": anonymous_cid,
			"client_id": client_dict["_id"],
			"track_id": track_id,
			"fi": from_info})

		# Add an audit entry
		await self.AuditService.append(
			AuditCode.ANONYMOUS_SESSION_CREATED,
			credentials_id=anonymous_cid,
			client_id=client_dict["_id"],
			session_id=str(session.Session.Id),
			fi=from_info)

		return session


	async def build_userinfo(self, session):
		# TODO: Session object should only serve as a cache
		#   After the cache has expired, update session object with fresh credential, authn and authz data
		#   and rebuild the userinfo

		otp_service = self.App.get_service("seacatauth.OTPService")

		userinfo = {
			"iss": self.Issuer,
			"sub": session.Credentials.Id,  # The sub (subject) Claim MUST always be returned in the UserInfo Response.
			"iat": session.CreatedAt,
			"sid": session.SessionId,
		}

		if session.Session.Expiration is not None:
			userinfo["exp"] = session.Session.Expiration

		if session.Session.ParentSessionId is not None:
			userinfo["psid"] = session.Session.ParentSessionId

		if session.OAuth2.ClientId is not None:
			# aud indicates who is allowed to consume the token
			# azp indicates who is allowed to present it
			userinfo["aud"] = session.OAuth2.ClientId
			userinfo["azp"] = session.OAuth2.ClientId

		if session.OAuth2.Scope is not None:
			userinfo["scope"] = session.OAuth2.Scope

		if session.OAuth2.Nonce is not None:
			userinfo["nonce"] = session.OAuth2.Nonce

		if session.Credentials.Username is not None:
			userinfo["preferred_username"] = session.Credentials.Username
			userinfo["username"] = session.Credentials.Username  # BACK-COMPAT, remove after 2023-01-31

		if session.Credentials.Email is not None:
			userinfo["email"] = session.Credentials.Email

		if session.Credentials.Phone is not None:
			userinfo["phone_number"] = session.Credentials.Phone
			userinfo["phone"] = session.Credentials.Phone  # BACK-COMPAT, remove after 2023-01-31

		if session.Credentials.CustomData is not None:
			userinfo["custom"] = session.Credentials.CustomData

		if session.Credentials.ModifiedAt is not None:
			userinfo["updated_at"] = session.Credentials.ModifiedAt

		if session.Credentials.CreatedAt is not None:
			userinfo["created_at"] = session.Credentials.CreatedAt

		if session.is_anonymous():
			userinfo["anonymous"] = True

		if session.TrackId is not None:
			track_id_hex = session.TrackId.hex()
			track_id = "{}-{}-{}-{}-{}".format(
				track_id_hex[:8],
				track_id_hex[8:12],
				track_id_hex[12:16],
				track_id_hex[16:20],
				track_id_hex[20:],)
			userinfo["track_id"] = track_id

		if session.Authentication.ImpersonatorSessionId:
			userinfo["impersonator_sid"] = session.Authentication.ImpersonatorSessionId
			userinfo["impersonator_cid"] = session.Authentication.ImpersonatorCredentialsId

		if await otp_service.has_activated_totp(session.Credentials.Id):
			userinfo["totp_set"] = True

		if session.Authentication.AvailableFactors is not None:
			userinfo["available_factors"] = session.Authentication.AvailableFactors

		if session.Authentication.LoginDescriptor is not None:
			userinfo["ldid"] = session.Authentication.LoginDescriptor
		if session.Authentication.LoginFactors is not None:
			userinfo["factors"] = session.Authentication.LoginFactors

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


	async def audit_authorize_error(self, client_id: str, error_message: str, credential_id: str = None, **kwargs):
		await self.AuditService.append(
			AuditCode.AUTHORIZE_ERROR,
			credentials_id=credential_id,
			client_id=client_id,
			errmsg=error_message,
			**kwargs)


	def build_authorize_uri(self, client_dict: dict, **query_params):
		"""
		Check if the client has a registered OAuth Authorize URI. If not, use the default.
		Extend the URI with query parameters.
		"""
		# TODO: This should be removed. There must be only one authorize endpoint.
		authorize_uri = client_dict.get("authorize_uri")
		if authorize_uri is None:
			authorize_uri = "{}{}".format(self.PublicApiBaseUrl, self.AuthorizePath.lstrip("/"))
		return add_params_to_url_query(authorize_uri, **{k: v for k, v in query_params.items() if v is not None})


	async def revoke_token(self, token, token_type_hint=None):
		"""
		Invalidate a valid token. Currently only access_token type is supported.
		"""
		session: SessionAdapter = await self.get_session_by_access_token(token)
		if session is not None:
			await self.SessionService.delete(session.SessionId)
