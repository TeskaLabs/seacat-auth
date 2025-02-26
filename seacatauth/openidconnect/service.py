import binascii
import datetime
import json
import base64
import logging
import typing
import asab
import asab.web.rest
import asab.exceptions
import aiohttp.web
import urllib.parse
import jwcrypto.jwt
import jwcrypto.jwk
import jwcrypto.jws

from ..models.const import ResourceId
from ..generic import update_url_query_params
from ..models import Session
from .. import exceptions
from . import pkce
from ..authz import build_credentials_authz


L = logging.getLogger(__name__)


# TODO: Use JWA algorithms?


class AuthorizationCode:
	TokenType = "oac"
	ByteLength = asab.Config.getint("openidconnect", "authorization_code_length")
	Expiration = asab.Config.getseconds("openidconnect", "authorization_code_expiration")


class AccessToken:
	TokenType = "oat"
	ByteLength = asab.Config.getint("openidconnect", "access_token_length")
	Expiration = asab.Config.getseconds("openidconnect", "access_token_expiration")


class RefreshToken:
	TokenType = "ort"
	ByteLength = asab.Config.getint("openidconnect", "refresh_token_length")
	Expiration = asab.Config.getseconds("openidconnect", "refresh_token_expiration")


class OpenIdConnectService(asab.Service):

	# Bearer token Regex is based on RFC 6750
	# The OAuth 2.0 Authorization Framework: Bearer Token Usage
	# Chapter 2.1. Authorization Request Header Field
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
		self.TokenService = app.get_service("seacatauth.SessionTokenService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.ClientService = app.get_service("seacatauth.ClientService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.RBACService = app.get_service("seacatauth.RBACService")
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.LastActivityService = app.get_service("seacatauth.LastActivityService")
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

		self.DisableRedirectUriValidation = asab.Config.getboolean(
			"openidconnect", "_disable_redirect_uri_validation", fallback=False)
		if self.DisableRedirectUriValidation:
			# This is a dev-only option
			L.warning("Redirect URI validation in OpenID Authorize requests is disabled.")

		# TODO: Derive the private key
		self.PrivateKey = app.PrivateKey

		self.JSONDumper = asab.web.rest.json.JSONDumper(pretty=False)


	async def refresh_session(
		self,
		session: Session,
		expires_at: typing.Optional[datetime.datetime] = None,
		requested_scope: typing.Optional[typing.Iterable] = None,
	) -> Session:
		"""
		Update/rebuild the session according to its authorization parameters

		Args:
			session: Session to refresh
			expires_at: New expiration time
			requested_scope: Requested scope

		Returns:
			Updated session
		"""
		# Get parent session
		root_session = await self.SessionService.get(session.Session.ParentSessionId)

		# Check that the requested scope is a subset of granted scope
		if requested_scope is not None:
			requested_scope = set(requested_scope)
			unauthorized_scope = requested_scope - set(session.OAuth2.Scope)
			if len(unauthorized_scope) > 0:
				raise exceptions.AccessDeniedError(
					"Client requested unauthorized scope.",
					subject=session.OAuth2.ClientId,
					resource=unauthorized_scope
				)
			granted_scope = requested_scope
		else:
			granted_scope = session.OAuth2.Scope

		# TODO: Differentiate between the scope granted at authorization time and the sub-scope requested for this token

		# Exclude critical resource grants from impersonated sessions
		if root_session.Authentication.ImpersonatorSessionId is not None:
			exclude_resources = {ResourceId.SUPERUSER, ResourceId.IMPERSONATE}
		else:
			exclude_resources = set()

		# Authorize tenant
		authz = await build_credentials_authz(
			self.TenantService, self.RoleService, root_session.Credentials.Id,
			tenants=None,
			exclude_resources=exclude_resources
		)
		authorized_tenant = await self.get_accessible_tenant_from_scope(
			granted_scope, root_session.Credentials.Id,
			has_access_to_all_tenants=self.RBACService.can_access_all_tenants(authz)
		)

		session_builders = await self.SessionService.build_client_session(
			root_session,
			client_id=session.OAuth2.ClientId,
			scope=granted_scope,
			tenants=[authorized_tenant] if authorized_tenant else None,
			nonce=session.OAuth2.Nonce,
			redirect_uri=session.OAuth2.RedirectUri,
		)

		if expires_at:
			session_builders.append(((Session.FN.Session.Expiration, expires_at),))

		session = await self.SessionService.update_session(session.SessionId, session_builders)

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


	def check_access_token(self, bearer_token):
		# TODO: this is not implemented
		L.error("check_access_token is not implemented", struct_data={"bearer": bearer_token})
		return aiohttp.web.HTTPNotImplemented()


	async def create_oidc_session(
		self, root_session, client_id, scope,
		nonce=None,
		redirect_uri=None,
		tenants=None,
		requested_expiration=None
	):
		session_builders = await self.SessionService.build_client_session(
			root_session,
			client_id,
			scope=scope,
			tenants=tenants,
			nonce=nonce,
			redirect_uri=redirect_uri
		)
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
		redirect_uri: list = None,
		from_info=None,
	):
		session = await self.SessionService.Algorithmic.create_anonymous_session(
			created_at=datetime.datetime.now(datetime.timezone.utc),
			track_id=track_id,
			client_dict=client_dict,
			scope=scope,
			redirect_uri=redirect_uri,
		)

		session.OAuth2.AccessToken = self.SessionService.Algorithmic.serialize(session)
		return session


	async def build_userinfo(self, session):
		otp_service = self.App.get_service("seacatauth.OTPService")

		userinfo = {
			"iss": self.Issuer,
			"sub": session.Credentials.Id,  # The sub (subject) Claim MUST always be returned in the UserInfo Response.
			"iat": session.ModifiedAt,  # "Issued-at" corresponds to the timestamp when the session was last updated
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

		if session.Authorization.AssignedTenants is not None:
			userinfo["tenants"] = session.Authorization.AssignedTenants

		# TODO: Last password change

		# RFC 7519 states that the exp and iat claim values must be NumericDate values
		# Convert ALL datetimes to UTC timestamps for consistency
		for k, v in userinfo.items():
			if isinstance(v, datetime.datetime):
				userinfo[k] = int(v.timestamp())

		return userinfo


	async def issue_id_token(self, session, expires_at: datetime.datetime | None = None):
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

		payload["iat"] = int(datetime.datetime.now(datetime.UTC).timestamp())
		if expires_at:
			payload["exp"] = int(expires_at.timestamp())

		token = jwcrypto.jwt.JWT(
			header=header,
			claims=self.JSONDumper(payload)
		)
		token.make_signed_token(self.PrivateKey)
		id_token = token.serialize()

		return id_token


	async def authorize_tenants_by_scope(self, scope, session, client_id):
		has_access_to_all_tenants = self.RBACService.has_resource_access(
			session.Authorization.Authz, tenant=None, requested_resources=[ResourceId.SUPERUSER]) \
			or self.RBACService.has_resource_access(
			session.Authorization.Authz, tenant=None, requested_resources=[ResourceId.ACCESS_ALL_TENANTS])
		try:
			tenants = await self.TenantService.get_tenants_by_scope(
				scope, session.Credentials.Id, has_access_to_all_tenants)
		except exceptions.TenantNotFoundError as e:
			L.error("Tenant not found", struct_data={"tenant": e.Tenant})
			raise exceptions.AccessDeniedError(subject=session.Credentials.Id)
		except exceptions.TenantAccessDeniedError as e:
			L.error("Tenant access denied", struct_data={"tenant": e.Tenant, "cid": session.Credentials.Id})
			raise exceptions.AccessDeniedError(subject=session.Credentials.Id)
		except exceptions.NoTenantsError:
			L.error("Tenant access denied", struct_data={"cid": session.Credentials.Id})
			raise exceptions.AccessDeniedError(subject=session.Credentials.Id)

		return tenants


	def build_authorize_uri(self, client_dict: dict, **query_params):
		"""
		Check if the client has a registered OAuth Authorize URI. If not, use the default.
		Extend the URI with query parameters.
		"""
		# TODO: This should be removed. There must be only one authorize endpoint.
		authorize_uri = client_dict.get("authorize_uri")
		if authorize_uri is None:
			authorize_uri = "{}{}".format(self.PublicApiBaseUrl, self.AuthorizePath.lstrip("/"))
		return update_url_query_params(authorize_uri, **{k: v for k, v in query_params.items() if v is not None})


	async def revoke_token(self, token, token_type_hint=None):
		"""
		Invalidate a valid token. Currently only access_token type is supported.
		"""
		try:
			session: Session = await self.get_session_by_access_token(token)
		except exceptions.SessionNotFoundError:
			return

		await self.SessionService.delete(session.SessionId)


	async def get_accessible_tenant_from_scope(
		self,
		scope: typing.Iterable,
		credentials_id: str,
		has_access_to_all_tenants: bool = False
	) -> typing.Optional[str]:
		"""
		Extract tenants from requested scope and return the first accessible one.
		"""
		try:
			tenants: set = await self.TenantService.get_tenants_by_scope(
				scope, credentials_id, has_access_to_all_tenants)
		except exceptions.TenantNotFoundError as e:
			L.error("Tenant not found.", struct_data={"tenant": e.Tenant})
			raise exceptions.AccessDeniedError(subject=credentials_id)
		except exceptions.TenantAccessDeniedError as e:
			L.log(asab.LOG_NOTICE, "Tenant access denied.", struct_data={"tenant": e.Tenant, "cid": credentials_id})
			raise exceptions.AccessDeniedError(subject=credentials_id)

		if tenants:
			return tenants.pop()
		else:
			return None


	async def calculate_token_expiration(
		self,
		session,
	) -> typing.Tuple[datetime.datetime, typing.Optional[datetime.datetime]]:
		"""
		Calculate the new expiration time of the client session's tokens
		"""
		# Get the parent SSO session's max expiration time
		sso_session = await self.SessionService.get(session.Session.ParentSessionId)

		# Determine the desired access and refresh token expiration time
		client_id = session.OAuth2.ClientId
		client = await self.ClientService.get(client_id)
		access_token_expiration = client.get("session_expiration") or AccessToken.Expiration
		access_token_expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
			seconds=access_token_expiration)

		if access_token_expires_at > sso_session.Session.MaxExpiration:
			# Maximum session lifetime reached, there will be no refresh token
			access_token_expires_at = sso_session.Session.MaxExpiration
			return access_token_expires_at, None

		refresh_token_expires_at = min(
			datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=RefreshToken.Expiration),
			sso_session.Session.MaxExpiration,
		)
		return access_token_expires_at, refresh_token_expires_at


	async def create_authorization_code(
		self, session: Session,
		code_challenge: str | None = None,
		code_challenge_method: str | None = None,
	) -> str:
		"""
		Create OAuth2 authorization code

		Args:
			session: Client session
			code_challenge: PKCE challenge string
			code_challenge_method: PKCE verification method

		Returns:
			Base64-encoded token value
		"""
		expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=AuthorizationCode.Expiration)
		if session.is_algorithmic():
			raw_value = await self.TokenService.create(
				token_length=AuthorizationCode.ByteLength,
				token_type=AuthorizationCode.TokenType,
				session_id=self.SessionService.Algorithmic.serialize(session),
				expires_at=expires_at,
				is_session_algorithmic=True,
				cc=code_challenge,
				ccm=code_challenge_method,
			)
		else:
			raw_value = await self.TokenService.create(
				token_length=AuthorizationCode.ByteLength,
				token_type=AuthorizationCode.TokenType,
				session_id=session.SessionId,
				expires_at=expires_at,
				is_session_algorithmic=False,
				cc=code_challenge,
				ccm=code_challenge_method,
			)
		return base64.urlsafe_b64encode(raw_value).decode("ascii")


	async def create_access_token(
		self,
		session: Session,
		expires_at: datetime.datetime,
	) -> str:
		"""
		Create OAuth2 access token

		Args:
			session: Client session
			expires_at: Token expiration time

		Returns:
			Base64-encoded token value
		"""
		raw_value = await self.TokenService.create(
			token_length=AccessToken.ByteLength,
			token_type=AccessToken.TokenType,
			session_id=session.SessionId,
			expires_at=expires_at,
			is_session_algorithmic=session.is_algorithmic(),
		)
		return base64.urlsafe_b64encode(raw_value).decode("ascii")


	async def create_refresh_token(
		self,
		session: Session,
		expires_at: datetime.datetime,
	) -> str:
		"""
		Create OAuth2 refresh token

		Args:
			session: Client session
			expires_at: Token expiration time

		Returns:
			Base64-encoded token value
		"""
		assert not session.is_algorithmic()
		raw_value = await self.TokenService.create(
			token_length=RefreshToken.ByteLength,
			token_type=RefreshToken.TokenType,
			session_id=session.SessionId,
			expires_at=expires_at,
		)
		return base64.urlsafe_b64encode(raw_value).decode("ascii")


	async def get_session_by_authorization_code(self, code, code_verifier: str | None = None):
		"""
		Retrieve session by its temporary authorization code.
		"""
		try:
			token_bytes = base64.urlsafe_b64decode(code.encode("ascii"))
		except binascii.Error as e:
			L.error("Corrupt authorization code format: Base64 decoding failed.", struct_data={"code": code})
			raise exceptions.SessionNotFoundError("Corrupt authorization code format") from e
		except UnicodeEncodeError as e:
			L.error("Corrupt authorization code format: ASCII decoding failed.", struct_data={"code": code})
			raise exceptions.SessionNotFoundError("Corrupt authorization code format") from e

		token_data = await self.TokenService.get(token_bytes, token_type=AuthorizationCode.TokenType)
		if "cc" in token_data:
			self.PKCE.evaluate_code_challenge(
				code_challenge_method=token_data["ccm"],
				code_challenge=token_data["cc"],
				code_verifier=code_verifier)
		if token_data.get("sa"):
			# Session is algorithmic (self-encoded token)
			return await self.SessionService.Algorithmic.deserialize(token_data["sid"])
		else:
			# Session is in the DB
			return await self.SessionService.get(token_data["sid"])


	async def get_session_by_access_token(self, token_value: str):
		"""
		Retrieve session by its access token.
		"""
		if "." in token_value:
			# If there is ".", the value is not pure base64. It must be a JWT of an algorithmic session.
			return await self.SessionService.Algorithmic.deserialize(token_value)

		try:
			token_bytes = base64.urlsafe_b64decode(token_value.encode("ascii"))
		except binascii.Error as e:
			L.error("Corrupt access token format: Base64 decoding failed.", struct_data={
				"token_value": token_value})
			raise exceptions.SessionNotFoundError("Corrupt access token format") from e
		except UnicodeEncodeError as e:
			L.error("Corrupt access token format: ASCII decoding failed.", struct_data={
				"token_value": token_value})
			raise exceptions.SessionNotFoundError("Corrupt access token format") from e

		try:
			token_data = await self.TokenService.get(token_bytes, token_type=AccessToken.TokenType)
		except KeyError:
			raise exceptions.SessionNotFoundError("Invalid or expired access token")
		try:
			session = await self.SessionService.get(token_data["sid"])
		except KeyError:
			L.error("Integrity error: Access token points to a nonexistent session.", struct_data={
				"sid": token_data["sid"]})
			await self.TokenService.delete(token_bytes)
			raise exceptions.SessionNotFoundError("Access token points to a nonexistent session")

		# Session expiry date must be the same as the expiration of its ACCESS token,
		# and it should be deleted after its REFRESH token expires.
		# TODO: This is a hotfix. Replace with a systemic solution.
		session.Session.Expiration = token_data["exp"]

		return session


	async def get_session_by_refresh_token(self, token_value: str):
		"""
		Retrieve session by its refresh token.
		"""
		try:
			token_bytes = base64.urlsafe_b64decode(token_value.encode("ascii"))
		except binascii.Error as e:
			L.error("Corrupt refresh token format: Base64 decoding failed.", struct_data={
				"token_value": token_value})
			raise exceptions.SessionNotFoundError("Corrupt refresh token format") from e
		except UnicodeEncodeError as e:
			L.error("Corrupt refresh token format: ASCII decoding failed.", struct_data={
				"token_value": token_value})
			raise exceptions.SessionNotFoundError("Corrupt refresh token format") from e

		try:
			token_data = await self.TokenService.get(token_bytes, token_type=RefreshToken.TokenType)
		except KeyError:
			raise exceptions.SessionNotFoundError("Invalid or expired refresh token")
		try:
			session = await self.SessionService.get(token_data["sid"])
		except KeyError:
			L.error("Integrity error: Refresh token points to a nonexistent session.", struct_data={
				"sid": token_data["sid"]})
			await self.TokenService.delete(token_bytes)
			raise exceptions.SessionNotFoundError("Refresh token points to a nonexistent session")

		return session


	async def delete_authorization_code(self, code: str):
		"""
		Delete temporary authorization code.
		"""
		token_bytes = base64.urlsafe_b64decode(code.encode("ascii"))
		await self.TokenService.delete(token_bytes)
