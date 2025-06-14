import datetime
import logging
import aiohttp.web
import jwcrypto.jws
import jwcrypto.jwt
import json
import asab
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.web.rest.json
import asab.exceptions

from .. import pkce
from ..utils import TokenRequestErrorResponseCode
from ... import exceptions, AuditLogger
from ... import generic
from . import schema
from ...models import const


L = logging.getLogger(__name__)


class TokenHandler(object):
	"""
	OAuth 2.0 Token request

	---
	tags: ["OAuth 2.0 / OpenID Connect"]
	"""

	def __init__(self, app, oidc_svc):
		self.OpenIdConnectService = oidc_svc
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.CookieService = app.get_service("seacatauth.CookieService")

		self.ValidateRedirectUri = asab.Config.getboolean(
			"openidconnect:token_request", "validate_redirect_uri", fallback=False)

		web_app = app.WebContainer.WebApp
		web_app.router.add_post(self.OpenIdConnectService.TokenPath, self.token_request)
		web_app.router.add_post(self.OpenIdConnectService.TokenRevokePath, self.token_revoke)
		web_app.router.add_put("/openidconnect/token/validate", self.validate_id_token)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_post(self.OpenIdConnectService.TokenPath, self.token_request)
		web_app_public.router.add_post(self.OpenIdConnectService.TokenRevokePath, self.token_revoke)
		web_app_public.router.add_put("/openidconnect/token/validate", self.validate_id_token)


	@asab.web.auth.noauth
	@asab.web.tenant.allow_no_tenant
	async def token_request(self, request):
		"""
		OAuth 2.0 Token Request

		---
		requestBody:
			content:
				application/x-www-form-urlencoded:
					schema:
						type: object
						properties:
							grant_type:
								type: string
								enum: ["authorization_code", "refresh_token"]
								description: The type of grant being requested
							code:
								type: string
								description: The authorization code returned by the authorization server
							refresh_token:
								type: string
								description: The refresh token returned by the authorization server
							redirect_uri:
								type: string
								description: The redirect URI that was used in the initial authorization request
							client_id:
								type: string
								description: The client ID issued by the authorization server
							client_secret:
								type: string
								description: The client secret issued by the authorization server
							code_verifier:
								type: string
								description:
									A cryptographically random string that is used to correlate the authorization
									request to the token request.
						required:
							- grant_type
		"""
		form_data = await request.post()
		from_ip = generic.get_request_access_ips(request)

		# Authenticate the client
		try:
			client = await self.OpenIdConnectService.ClientService.authenticate_client_request(request)
		except exceptions.ClientAuthenticationError as e:
			AuditLogger.log(asab.LOG_NOTICE, "Token request denied: Unauthorized client.", struct_data={
				"from_ip": from_ip,
				"client_id": e.ClientID,
				"redirect_uri": form_data.get("redirect_uri"),
			})
			return self.token_error_response(request, TokenRequestErrorResponseCode.UnauthorizedClient)

		# Choose flow based on grant_type
		grant_type = form_data.get("grant_type")
		if grant_type == const.OAuth2.GrantType.AUTHORIZATION_CODE:
			process_token_request = self._authorization_code_grant(request, client, from_ip)
		elif grant_type == const.OAuth2.GrantType.REFRESH_TOKEN:
			process_token_request = self._refresh_token_grant(request, client, from_ip)
		elif grant_type == const.OAuth2.GrantType.CLIENT_CREDENTIALS:
			process_token_request = self._client_credentials_grant(request, client, from_ip)
		else:
			AuditLogger.log(asab.LOG_NOTICE, "Token request denied: Unsupported grant type.", struct_data={
				"from_ip": from_ip,
				"grant_type": grant_type,
				"client_id": form_data.get("client_id"),
				"redirect_uri": form_data.get("redirect_uri"),
			})
			return self.token_error_response(request, TokenRequestErrorResponseCode.UnsupportedGrantType)

		try:
			return await process_token_request
		except exceptions.ClientAuthenticationError as e:
			AuditLogger.log(asab.LOG_NOTICE, "Token request denied: Unauthorized client.", struct_data={
				"from_ip": from_ip,
				"grant_type": grant_type,
				"client_id": e.ClientID,
				"redirect_uri": form_data.get("redirect_uri"),
			})
			return self.token_error_response(request, TokenRequestErrorResponseCode.UnauthorizedClient)
		except exceptions.OAuth2InvalidClient as e:
			AuditLogger.log(asab.LOG_NOTICE, "Token request denied: Invalid client.", struct_data={
				"from_ip": from_ip,
				"grant_type": grant_type,
				"client_id": e.ClientId,
				"redirect_uri": form_data.get("redirect_uri"),
			})
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidClient)
		except exceptions.OAuth2InvalidScope as e:
			AuditLogger.log(asab.LOG_NOTICE, "Token request denied: Invalid scope.", struct_data={
				"from_ip": from_ip,
				"grant_type": grant_type,
				"client_id": e.ClientId,
				"scope": e.Scope,
				"redirect_uri": form_data.get("redirect_uri"),
			})
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidScope)


	async def _authorization_code_grant(
		self,
		request: aiohttp.web.Request,
		client: dict,
		from_ip: list
	) -> aiohttp.web.Response:

		form_data = await request.post()
		client_id = client["_id"]

		# Get session by code
		try:
			session = await self._get_session_by_authorization_code(request)

		except (exceptions.SessionNotFoundError, KeyError):
			AuditLogger.log(
				asab.LOG_NOTICE,
				"Token request denied: Invalid or expired authorization code.",
				struct_data={
					"from_ip": from_ip,
					"grant_type": const.OAuth2.GrantType.AUTHORIZATION_CODE,
					"client_id": client_id,
					"redirect_uri": form_data.get("redirect_uri"),
				}
			)
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidGrant)

		except pkce.CodeChallengeFailedError:
			AuditLogger.log(
				asab.LOG_NOTICE,
				"Token request denied: Code challenge failed.",
				struct_data={
					"from_ip": from_ip,
					"grant_type": const.OAuth2.GrantType.AUTHORIZATION_CODE,
					"client_id": client_id,
					"redirect_uri": form_data.get("redirect_uri"),
				}
			)
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidGrant)

		except exceptions.URLValidationError:
			AuditLogger.log(asab.LOG_NOTICE, "Token request denied: Redirect URI mismatch.", struct_data={
				"from_ip": from_ip,
				"grant_type": const.OAuth2.GrantType.AUTHORIZATION_CODE,
				"client_id": client_id,
				"redirect_uri": form_data.get("redirect_uri"),
			})
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidRequest)

		except asab.exceptions.ValidationError:
			AuditLogger.log(asab.LOG_NOTICE, "Token request denied: Invalid request.", struct_data={
				"from_ip": from_ip,
				"grant_type": const.OAuth2.GrantType.AUTHORIZATION_CODE,
				"client_id": client_id,
				"redirect_uri": form_data.get("redirect_uri"),
			})
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidRequest)

		if client_id != session.OAuth2.ClientId:
			raise exceptions.ClientAuthenticationError(
				"Client ID in token request does not match the one used in authorization request.")

		# Establish and propagate track ID
		session = await self.set_track_id(request, session, from_ip)

		# Everything is okay: Request granted
		AuditLogger.log(asab.LOG_NOTICE, "Token request granted.", struct_data={
			"cid": session.Credentials.Id,
			"sid": session.Id,
			"client_id": session.OAuth2.ClientId,
			"grant_type": const.OAuth2.GrantType.AUTHORIZATION_CODE,
			"from_ip": from_ip
		})

		# Client can limit the session scope to a subset of the scope granted at authorization time
		scope = form_data.get("scope")

		# Generate new auth tokens
		if session.is_algorithmic():
			new_access_token = self.SessionService.Algorithmic.serialize(session)
			response_payload = {
				"token_type": "Bearer",
				"scope": " ".join(session.OAuth2.Scope),
				"access_token": new_access_token,
				"id_token": await self.OpenIdConnectService.issue_id_token(session, expires_at=None),
			}
		else:
			response_payload = await self._refresh_session_and_issue_tokens(session, scope=scope)

		headers = {
			"Cache-Control": "no-store",
			"Pragma": "no-cache",
		}

		return asab.web.rest.json_response(request, response_payload, headers=headers)


	async def _refresh_token_grant(
		self,
		request: aiohttp.web.Request,
		client: dict,
		from_ip: list
	) -> aiohttp.web.Response:

		form_data = await request.post()
		client_id = client["_id"]

		# Get session by refresh token
		try:
			session = await self._get_session_by_refresh_token(request)

		except (exceptions.SessionNotFoundError, KeyError):
			AuditLogger.log(
				asab.LOG_NOTICE,
				"Token request denied: Invalid or expired refresh token.",
				struct_data={
					"from_ip": from_ip,
					"grant_type": const.OAuth2.GrantType.REFRESH_TOKEN,
					"client_id": client_id,
				}
			)
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidGrant)

		except exceptions.ClientAuthenticationError as e:
			AuditLogger.log(asab.LOG_NOTICE, "Token request denied: Cannot verify client.", struct_data={
				"from_ip": from_ip,
				"grant_type": const.OAuth2.GrantType.REFRESH_TOKEN,
				"client_id": e.ClientID,
			})
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidClient)

		# Refresh is not supported for algorithmic sessions (yet)
		assert not session.is_algorithmic()

		if client_id != session.OAuth2.ClientId:
			raise exceptions.ClientAuthenticationError(
				"Client ID in token request does not match the one used in authorization request.")

		# Delete the used refresh token and the current access token
		await self.SessionService.TokenService.delete_tokens_by_session_id(session.SessionId)

		# Everything is okay: Request granted
		AuditLogger.log(asab.LOG_NOTICE, "Token request granted.", struct_data={
			"cid": session.Credentials.Id,
			"sid": session.Id,
			"client_id": session.OAuth2.ClientId,
			"grant_type": const.OAuth2.GrantType.REFRESH_TOKEN,
			"from_ip": from_ip,
		})

		# Client can limit the session scope to a subset of the scope granted at authorization time
		scope = form_data.get("scope")

		response_payload = await self._refresh_session_and_issue_tokens(session, scope=scope)

		headers = {
			"Cache-Control": "no-store",
			"Pragma": "no-cache",
		}

		return asab.web.rest.json_response(request, response_payload, headers=headers)


	async def _client_credentials_grant(
		self,
		request: aiohttp.web.Request,
		client: dict,
		from_ip: list
	) -> aiohttp.web.Response:

		form_data = await request.post()
		client_id = client["_id"]

		if "scope" not in form_data:
			AuditLogger.log(
				asab.LOG_NOTICE,
				"Token request denied: Missing scope parameter.",
				struct_data={
					"from_ip": from_ip,
					"grant_type": const.OAuth2.GrantType.CLIENT_CREDENTIALS,
					"client_id": form_data.get("client_id"),
				}
			)
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidRequest)

		scope = form_data["scope"].split(" ")

		try:
			tokens = await self.OpenIdConnectService.issue_token_for_client_credentials(
				client_id=client_id,
				scope=scope,
			)

		except exceptions.CredentialsNotFoundError:
			AuditLogger.log(
				asab.LOG_NOTICE,
				"Token request denied: Client does not have Seacat Auth credentials enabled.",
				struct_data={
					"from_ip": from_ip,
					"grant_type": const.OAuth2.GrantType.CLIENT_CREDENTIALS,
					"client_id": client_id,
				}
			)
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidClient)

		except exceptions.NoTenantsError:
			AuditLogger.log(asab.LOG_NOTICE, "Token request denied: Client has no tenants.", struct_data={
				"from_ip": from_ip,
				"grant_type": const.OAuth2.GrantType.CLIENT_CREDENTIALS,
				"client_id": client_id,
				"scope": " ".join(scope),
			})
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidScope)

		except exceptions.AccessDeniedError:
			AuditLogger.log(asab.LOG_NOTICE, "Token request denied: Unauthorized tenant access.", struct_data={
				"from_ip": from_ip,
				"grant_type": const.OAuth2.GrantType.CLIENT_CREDENTIALS,
				"client_id": client_id,
				"scope": " ".join(scope),
			})
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidScope)

		# Token request successful
		session = tokens["session"]
		AuditLogger.log(asab.LOG_NOTICE, "Token request granted.", struct_data={
			"cid": session.Credentials.Id,
			"sid": session.SessionId,
			"client_id": client_id,
			"grant_type": const.OAuth2.GrantType.CLIENT_CREDENTIALS,
			"from_ip": from_ip,
		})

		response_payload = {
			"token_type": "Bearer",
			"scope": " ".join(session.OAuth2.Scope),
			"access_token": tokens["access_token"],
			"expires_in": int((session.Session.Expiration - datetime.datetime.now(datetime.UTC)).total_seconds()),
		}

		headers = {
			"Cache-Control": "no-store",
			"Pragma": "no-cache",
		}

		return asab.web.rest.json_response(request, response_payload, headers=headers)


	async def _refresh_session_and_issue_tokens(self, session, scope=None):
		"""
		Refresh the client session, its parent SSO session and generate new tokens.
		"""
		# Calculate the new expiration time of the client session's tokens
		access_token_expires_at, refresh_token_expires_at = \
			await self.OpenIdConnectService.calculate_token_expiration(session)

		# Extend the parent SSO session
		if refresh_token_expires_at:
			await self.SessionService.update_session_expiration(
				session.Session.ParentSessionId, expires_at=refresh_token_expires_at)

		# Refresh the client session
		session = await self.OpenIdConnectService.refresh_session(
			session, requested_scope=scope, expires_at=refresh_token_expires_at)

		# Generate new tokens
		new_access_token = await self.OpenIdConnectService.create_access_token(
			session, expires_at=access_token_expires_at)
		new_id_token = await self.OpenIdConnectService.issue_id_token(session, access_token_expires_at)

		response_payload = {
			"token_type": "Bearer",
			"scope": " ".join(session.OAuth2.Scope),
			"access_token": new_access_token,
			"id_token": new_id_token,
			"expires_in": int((access_token_expires_at - datetime.datetime.now(datetime.UTC)).total_seconds()),
		}

		if refresh_token_expires_at:
			new_refresh_token = await self.OpenIdConnectService.create_refresh_token(
				session, expires_at=refresh_token_expires_at)
			response_payload["refresh_token"] = new_refresh_token

		return response_payload


	async def _get_session_by_authorization_code(self, request):
		form_data = await request.post()

		authorization_code = form_data.get("code")
		if not authorization_code:
			raise asab.exceptions.ValidationError("No authorization code in request.")

		# Locate the session by authorization code
		session = await self.OpenIdConnectService.get_session_by_authorization_code(
			authorization_code, form_data.get("code_verifier"))

		# TODO: If possible, verify that the Authorization Code has not been previously used.

		if self.ValidateRedirectUri:
			# Ensure that the redirect_uri parameter value is identical to the redirect_uri parameter value
			# that was included in the initial Authorization Request.
			# TODO: If the redirect_uri parameter value is not present when there is only one registered
			#  redirect_uri value, the Authorization Server MAY return an error (since the Client should have
			#  included the parameter) or MAY proceed without an error
			redirect_uri = form_data.get("redirect_uri")
			if redirect_uri != session.OAuth2.RedirectUri:
				raise exceptions.ClientAuthenticationError(
					"Redirect URI in token request does not match the one used in authorization request.")

		# Request valid, code is consumed
		await self.OpenIdConnectService.delete_authorization_code(authorization_code)

		return session


	async def _get_session_by_refresh_token(self, request):
		form_data = await request.post()
		refresh_token = form_data.get("refresh_token")
		if not refresh_token:
			raise asab.exceptions.ValidationError("No refresh token in request.")

		# Locate the session
		session = await self.OpenIdConnectService.get_session_by_refresh_token(refresh_token)

		# TODO: If possible, verify that the Refresh Token has not been previously used.

		return session


	@asab.web.rest.json_schema_handler(schema.TOKEN_REVOKE)
	@asab.web.auth.noauth
	@asab.web.tenant.allow_no_tenant
	async def token_revoke(self, request, *, json_data):
		"""
		OAuth 2.0 Token revocation

		https://tools.ietf.org/html/rfc7009
		"""
		# TODO: Confidential clients must authenticate (query params or Authorization header)
		# TODO: Public clients are not allowed to revoke other clients' tokens
		token_type_hint = json_data.get("token_type_hint")  # Optional `access_token` or `refresh_token`
		await self.OpenIdConnectService.revoke_token(json_data["token"], token_type_hint)
		return aiohttp.web.HTTPOk()


	def token_error_response(self, request, error, error_description=None):
		"""
		3.1.3.4.  Token Error Response
		"""

		response = {"error": error}
		if error_description:
			response["error_description"] = error_description
		return asab.web.rest.json_response(request, response, headers={
			"Cache-Control": "no-store",
			"Pragma": "no-cache",
		}, status=400)


	# TODO: Remove. This is basically token introspection.
	@asab.web.auth.noauth
	@asab.web.tenant.allow_no_tenant
	async def validate_id_token(self, request):
		"""
		Check the validity of a JWToken

		Read the JWToken either from the request body or from the Authorization header.
		Validate the token: send back the contents if successful; otherwise respond with error.
		"""
		body = await request.read()
		auth_header: str = request.headers.get("Authorization", "")
		if len(body) > 0:
			token_string = body.decode("ascii")
		elif auth_header.startswith("Bearer "):
			token_string = request.headers["Authorization"][len("Bearer "):]
		else:
			raise asab.exceptions.ValidationError("No ID token found in request body or Authorization header.")

		try:
			token = jwcrypto.jwt.JWT(jwt=token_string, key=self.OpenIdConnectService.PrivateKey)
		except ValueError as e:
			return asab.web.rest.json_response(request, {"error": str(e)}, status=400)
		except jwcrypto.jwt.JWTExpired:
			return asab.web.rest.json_response(request, {"error": "ID token expired"}, status=401)
		except jwcrypto.jws.InvalidJWSSignature:
			return asab.web.rest.json_response(request, {"error": "Invalid ID token signature"}, status=401)

		try:
			token_payload = json.loads(token.claims)
		except ValueError:
			return asab.web.rest.json_response(request, {"error": "Cannot parse token claims"}, status=400)

		return asab.web.rest.json_response(request, token_payload)


	async def set_track_id(self, request, session, from_ip):
		# Set track ID if not set yet
		if session.TrackId is None:
			session = await self.SessionService.inherit_track_id_from_root(session)
		if session.TrackId is None:
			# Obtain the old session by request access token or cookie
			token_value = generic.get_bearer_token_value(request)
			if token_value is not None:
				try:
					old_session = await self.OpenIdConnectService.get_session_by_access_token(token_value)
				except exceptions.SessionNotFoundError:
					AuditLogger.log(
						asab.LOG_NOTICE,
						"Token request denied: Track ID transfer failed because of invalid Authorization header",
						struct_data={
							"from_ip": from_ip,
							"cid": session.Credentials.Id,
							"client_id": session.OAuth2.ClientId,
						}
					)
					return aiohttp.web.HTTPBadRequest()
			else:
				# Use cookie only if there is no access token
				try:
					old_session = await self.CookieService.get_session_by_request_cookie(
						request, session.OAuth2.ClientId)
				except exceptions.SessionNotFoundError:
					old_session = None
				except exceptions.NoCookieError:
					old_session = None

			try:
				session = await self.SessionService.inherit_or_generate_new_track_id(session, old_session)
			except ValueError as e:
				# Return 400 to prevent disclosure while keeping the stacktrace
				AuditLogger.log(
					asab.LOG_NOTICE,
					"Token request denied: Failed to produce session track ID",
					struct_data={
						"from_ip": from_ip,
						"cid": session.Credentials.Id,
						"client_id": session.OAuth2.ClientId,
					}
				)
				raise aiohttp.web.HTTPBadRequest() from e

		return session
