import base64
import logging
import datetime

import aiohttp.web

import asab
import asab.web.rest
import asab.web.rest.json
import asab.exceptions

import jwcrypto.jws
import jwcrypto.jwt
import json

from .. import pkce
from ..utils import TokenRequestErrorResponseCode
from ... import exceptions, AuditLogger
from ... import generic

#

L = logging.getLogger(__name__)

#


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
		self.AccessTokenExpiration = 3*60
		self.RefreshTokenExpiration = 60*60

		web_app = app.WebContainer.WebApp
		web_app.router.add_post(self.OpenIdConnectService.TokenPath, self.token_request)
		web_app.router.add_post(self.OpenIdConnectService.TokenRevokePath, self.token_revoke)
		web_app.router.add_put("/openidconnect/token/validate", self.validate_id_token)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_post(self.OpenIdConnectService.TokenPath, self.token_request)
		web_app_public.router.add_post(self.OpenIdConnectService.TokenRevokePath, self.token_revoke)
		web_app_public.router.add_put("/openidconnect/token/validate", self.validate_id_token)


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

		# 3.1.3.2.  Token Request Validation
		grant_type = form_data.get("grant_type")
		if grant_type == "authorization_code":
			return await self._authorization_code_grant(request, from_ip)
		elif grant_type == "refresh_token":
			return await self._refresh_token_grant(request, from_ip)
		else:
			AuditLogger.log(asab.LOG_NOTICE, "Token request denied: Unsupported grant type.", struct_data={
				"from_ip": from_ip,
				"grant_type": grant_type,
				"client_id": form_data.get("client_id"),
				"redirect_uri": form_data.get("redirect_uri"),
			})
			return self.token_error_response(request, TokenRequestErrorResponseCode.UnsupportedGrantType)


	async def _authorization_code_grant(self, request, from_ip):
		form_data = await request.post()

		# Get session by code
		try:
			session = await self._get_session_by_authorization_code(request)

		except (exceptions.SessionNotFoundError, KeyError):
			AuditLogger.log(
				asab.LOG_NOTICE,
				"Token request denied: Invalid or expired authorization code.",
				struct_data={
					"from_ip": from_ip,
					"grant_type": "authorization_code",
					"client_id": form_data.get("client_id"),
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
					"grant_type": "authorization_code",
					"client_id": form_data.get("client_id"),
					"redirect_uri": form_data.get("redirect_uri"),
				}
			)
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidGrant)

		except exceptions.ClientAuthenticationError as e:
			AuditLogger.log(asab.LOG_NOTICE, "Token request denied: Cannot verify client ({}).".format(e), struct_data={
				"from_ip": from_ip,
				"grant_type": "authorization_code",
				"client_id": form_data.get("client_id"),
				"redirect_uri": form_data.get("redirect_uri"),
			})
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidClient)

		except exceptions.URLValidationError:
			AuditLogger.log(asab.LOG_NOTICE, "Token request denied: Redirect URI mismatch.", struct_data={
				"from_ip": from_ip,
				"grant_type": "authorization_code",
				"client_id": form_data.get("client_id"),
				"redirect_uri": form_data.get("redirect_uri"),
			})
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidRequest)

		# Establish and propagate track ID
		session = await self.set_track_id(request, session, from_ip)

		# Everything is okay: Request granted
		AuditLogger.log(asab.LOG_NOTICE, "Token request granted.", struct_data={
			"cid": session.Credentials.Id,
			"sid": session.Id,
			"client_id": session.OAuth2.ClientId,
			"grant_type": "authorization_code",
			"from_ip": from_ip})

		# Generate new auth tokens
		if session.is_algorithmic():
			new_access_token = await self.SessionService.Algorithmic.serialize(session)
			expires_in = (session.Session.Expiration - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
			new_refresh_token = None
		else:
			new_access_token, expires_in = await self.OpenIdConnectService.create_access_token(session)
			new_refresh_token = await self.OpenIdConnectService.create_refresh_token(session)

		# Client can limit the session scope to a subset of the scope granted at authorization time
		scope = form_data.get("scope")

		# Refresh the session data
		session = await self.OpenIdConnectService.refresh_session(session, requested_scope=scope)

		# Response
		response_payload = {
			"token_type": "Bearer",
			"scope": " ".join(session.OAuth2.Scope),
			"access_token": new_access_token,
			"id_token": await self.OpenIdConnectService.issue_id_token(session, expires_in),
			"expires_in": int(expires_in),
		}

		if new_refresh_token:
			response_payload["refresh_token"] = new_refresh_token

		headers = {
			"Cache-Control": "no-store",
			"Pragma": "no-cache",
		}

		return asab.web.rest.json_response(request, response_payload, headers=headers)


	async def _refresh_token_grant(self, request, from_ip):
		form_data = await request.post()

		# Get session by refresh token
		try:
			session = await self._get_session_by_refresh_token(request)

		except (exceptions.SessionNotFoundError, KeyError):
			AuditLogger.log(
				asab.LOG_NOTICE,
				"Token request denied: Invalid or expired refresh token.",
				struct_data={
					"from_ip": from_ip,
					"grant_type": "refresh_token",
					"client_id": form_data.get("client_id"),
					"redirect_uri": form_data.get("redirect_uri"),
				}
			)
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidGrant)

		except exceptions.ClientAuthenticationError:
			AuditLogger.log(asab.LOG_NOTICE, "Token request denied: Cannot verify client.", struct_data={
				"from_ip": from_ip,
				"grant_type": "refresh_token",
				"client_id": form_data.get("client_id"),
				"redirect_uri": form_data.get("redirect_uri"),
			})
			return self.token_error_response(request, TokenRequestErrorResponseCode.InvalidClient)

		# Refresh is not supported for algorithmic sessions (yet)
		assert not session.is_algorithmic()

		# Everything is okay: Request granted
		AuditLogger.log(asab.LOG_NOTICE, "Token request granted.", struct_data={
			"cid": session.Credentials.Id,
			"sid": session.Id,
			"client_id": session.OAuth2.ClientId,
			"grant_type": "refresh_token",
			"from_ip": from_ip
		})

		# Delete the used refresh token and the current access token
		await self.SessionService.TokenService.delete_tokens_by_session_id(session.SessionId)

		# Generate new auth tokens
		new_access_token, expires_in = await self.OpenIdConnectService.create_access_token(session)
		new_refresh_token = await self.OpenIdConnectService.create_refresh_token(session)

		# Client can limit the session scope to a subset of the scope granted at authorization time
		scope = form_data.get("scope")

		# Refresh the session data
		session = await self.OpenIdConnectService.refresh_session(session, requested_scope=scope)

		# Response
		response_payload = {
			"token_type": "Bearer",
			"scope": " ".join(session.OAuth2.Scope),
			"access_token": new_access_token,
			"refresh_token": new_refresh_token,
			"id_token": await self.OpenIdConnectService.issue_id_token(session, expires_in),
			"expires_in": int(expires_in),
		}

		headers = {
			"Cache-Control": "no-store",
			"Pragma": "no-cache",
		}

		return asab.web.rest.json_response(request, response_payload, headers=headers)


	async def _get_session_by_authorization_code(self, request):
		form_data = await request.post()

		authorization_code = form_data.get("code")
		if not authorization_code:
			raise asab.exceptions.ValidationError("No authorization code in request.")

		# Locate the session by authorization code
		session = await self.OpenIdConnectService.get_session_by_authorization_code(
			authorization_code, form_data.get("code_verifier"))

		# TODO: If possible, verify that the Authorization Code has not been previously used.

		# Verify client credentials if required
		client_id = await self._authenticate_client(session, request)

		# Ensure the Authorization Code was issued to the authenticated Client
		if client_id != session.OAuth2.ClientId:
			raise exceptions.ClientAuthenticationError(
				"Client ID in token request does not match the one used in authorization request.")

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

		# Verify client credentials if required
		client_id = await self._authenticate_client(session, request)

		# Ensure the Authorization Code was issued to the authenticated Client
		if client_id != session.OAuth2.ClientId:
			raise exceptions.ClientAuthenticationError(
				"Client ID in token request does not match the one used in authorization request.")

		return session


	async def _authenticate_client(self, session, request) -> str:
		"""
		Verify client credentials and check that the Authorization Code was issued to the authenticated Client.

		@param session: Session object
		@param request: aiohttp request
		@return: Client ID
		"""
		client_dict = await self.OpenIdConnectService.ClientService.get(session.OAuth2.ClientId)
		token_endpoint_auth_method = client_dict["token_endpoint_auth_method"]
		if token_endpoint_auth_method == "none":
			return session.OAuth2.ClientId
		elif token_endpoint_auth_method == "client_secret_basic":
			auth_header = request.headers.get("Authorization")
			client_id, secret = base64.urlsafe_b64decode(auth_header.encode("ascii")).decode("ascii").split(":")
			await self.OpenIdConnectService.ClientService.authenticate_client(client_dict, client_id, secret)
		elif token_endpoint_auth_method == "client_secret_post":
			post_data = await request.post()
			client_id = post_data.get("client_id")
			secret = post_data.get("client_secret")
			await self.OpenIdConnectService.ClientService.authenticate_client(client_dict, client_id, secret)
		elif token_endpoint_auth_method == "client_secret_jwt":
			raise ValueError("Unsupported token_endpoint_auth_method value: {}".format(token_endpoint_auth_method))
		elif token_endpoint_auth_method == "private_key_jwt":
			raise ValueError("Unsupported token_endpoint_auth_method value: {}".format(token_endpoint_auth_method))
		else:
			raise ValueError("Unsupported token_endpoint_auth_method value: {}".format(token_endpoint_auth_method))

		return client_id


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": ["token"],
		"properties": {
			"token": {"type": "string"},
			"token_type_hint": {"type": "string"},
		}
	})
	async def token_revoke(self, request, *, json_data):
		"""
		https://tools.ietf.org/html/rfc7009

		2.1.  Revocation Request
		"""
		# TODO: Confidential clients must authenticate (query params or Authorization header)
		# TODO: Public clients are not allowed to revoke other clients' tokens
		if request.Session is None:
			return aiohttp.web.HTTPUnauthorized()

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


	async def validate_id_token(self, request):
		"""
		Read the JWT token either from the request body or from the Authorization header.
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
