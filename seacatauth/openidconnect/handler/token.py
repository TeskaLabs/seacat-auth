import logging
import urllib.parse
import datetime

import aiohttp.web

import asab
import asab.web.rest
import asab.web.rest.json
import asab.exceptions

import jwcrypto.jws
import jwcrypto.jwt
import json

from ..utils import TokenRequestErrorResponseCode
from ..pkce import CodeChallengeFailedError
from ...generic import get_bearer_token_value

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

		web_app = app.WebContainer.WebApp
		web_app.router.add_post("/openidconnect/token", self.token_request)
		web_app.router.add_post("/openidconnect/token/revoke", self.token_revoke)
		web_app.router.add_post("/openidconnect/token/refresh", self.token_refresh)
		web_app.router.add_put("/openidconnect/token/validate", self.validate_id_token)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_post("/openidconnect/token", self.token_request)
		web_app_public.router.add_post("/openidconnect/token/revoke", self.token_revoke)
		web_app_public.router.add_post("/openidconnect/token/refresh", self.token_refresh)
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
		data = await request.text()
		qs_data = dict(urllib.parse.parse_qsl(data))

		# 3.1.3.2.  Token Request Validation
		grant_type = qs_data.get("grant_type")

		if grant_type == "authorization_code":
			return await self._token_request_authorization_code(request, qs_data)

		L.error("Unsupported grant type: {}".format(grant_type))
		return aiohttp.web.HTTPBadRequest()


	async def _token_request_authorization_code(self, request, qs_data):
		"""
		https://openid.net/specs/openid-connect-core-1_0.html

		3.1.3.1.  Token Request

		Request contains query string such as:
		grant_type=authorization_code&code=foo-bar-code&redirect_uri=....

		"""

		# Ensure the Authorization Code was issued to the authenticated Client
		authorization_code = qs_data.get("code", "")
		if len(authorization_code) == 0:
			L.warning("Authorization Code not provided")
			return asab.web.rest.json_response(
				request, {"error": TokenRequestErrorResponseCode.InvalidRequest}, status=400)

		# Locate the session by authorization code
		try:
			new_session = await self.OpenIdConnectService.pop_session_by_authorization_code(authorization_code)
		except KeyError:
			L.warning("Session not found.", struct_data={"code": authorization_code})
			return asab.web.rest.json_response(
				request, {"error": TokenRequestErrorResponseCode.InvalidGrant}, status=400)

		if new_session.OAuth2.PKCE is not None:
			try:
				self.OpenIdConnectService.PKCE.evaluate_code_challenge(
					new_session.OAuth2.PKCE["method"],
					new_session.OAuth2.PKCE["challenge"],
					qs_data.get("code_verifier"))
			except CodeChallengeFailedError as e:
				L.log(asab.LOG_NOTICE, "Code challenge failed.", struct_data={"reason": str(e)})
				return asab.web.rest.json_response(
					request, {"error": TokenRequestErrorResponseCode.InvalidGrant}, status=400)
			except Exception as e:
				L.error("Code challenge error: {}".format(e), exc_info=True)
				return asab.web.rest.json_response(
					request, {"error": TokenRequestErrorResponseCode.InvalidGrant}, status=400)

		# TODO: Check if the redirect URL is the same as the one in the authorization request:
		#   if authorization_request.get("redirect_uri") != qs_data.get('redirect_uri'):
		# 	  return await self.token_error_response(request, "The redirect URL is not associated with the client.")

		# Set track ID if not set yet
		if new_session.TrackId is None:
			new_session = await self.SessionService.inherit_track_id_from_root(new_session)
		if new_session.TrackId is None:
			# Obtain the old session by request access token or cookie
			token_value = get_bearer_token_value(request)
			cookie_value = self.CookieService.get_session_cookie_value(request, new_session.OAuth2.ClientId)
			if token_value is not None:
				old_session = await self.OpenIdConnectService.get_session_by_access_token(token_value)
				if old_session is None:
					L.error("Cannot transfer Track ID: Invalid access token.", struct_data={"value": token_value})
					raise aiohttp.web.HTTPBadRequest()
			elif cookie_value is not None:
				old_session = await self.CookieService.get_session_by_session_cookie_value(cookie_value)
			else:
				old_session = None

			try:
				new_session = await self.SessionService.inherit_or_generate_new_track_id(new_session, old_session)
			except ValueError:
				raise aiohttp.web.HTTPBadRequest()

		headers = {
			"Cache-Control": "no-store",
			"Pragma": "no-cache",
		}

		expires_in = int((new_session.Session.Expiration - datetime.datetime.now(datetime.timezone.utc)).total_seconds())

		id_token = await self.OpenIdConnectService.build_id_token(new_session)

		# 3.1.3.3.  Successful Token Response
		body = {
			"token_type": "Bearer",
			"scope": " ".join(new_session.OAuth2.Scope),
			"access_token": new_session.OAuth2.AccessToken,
			"refresh_token": new_session.OAuth2.RefreshToken,
			"id_token": id_token,
			"expires_in": expires_in,
		}

		return asab.web.rest.json_response(request, body, headers=headers)


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
		OAuth 2.0 Access Token Revoke
		"""
		# TODO: this is not implemented

		if not self.OpenIdConnectService.check_access_token(request.headers["Authorization"].split()[1]):
			raise aiohttp.web.HTTPForbidden(reason="User is not authenticated")

		"""
		https://tools.ietf.org/html/rfc7009

		2.1.  Revocation Request
		"""

		token_type_hint = json_data.get("token_type_hint")  # Optional `access_token` or `refresh_token`
		if token_type_hint:
			if token_type_hint == "access_token":
				self.OpenIdConnectService.invalidate_access_token(json_data["token"])
			elif token_type_hint == "refresh_token":
				self.OpenIdConnectService.invalidate_refresh_token(json_data["token"])
			else:
				return await self.token_error_response(request, "Unknown token_type_hint {}".format(token_type_hint))
		self.OpenIdConnectService.invalidate_token(json_data["token"])
		return aiohttp.web.HTTPOk()


	@asab.web.rest.json_schema_handler({
		'type': 'object',
		'required': ['grant_type', 'client_id', 'scope', 'client_secret', 'refresh_token'],
		'properties': {
			'grant_type': {'type': 'string'},
			'client_id': {'type': 'string'},
			'scope': {'type': 'string'},
			'client_secret': {'type': 'string'},
			'refresh_token': {'type': 'string'},
		}
	})
	async def token_refresh(self, request, *, json_data):
		"""
		OAuth 2.0 Access Token Refresh
		"""
		# TODO: this is not implemented

		# scope = json_data['scope']  # TODO validate `scope` is the same as original

		token_id = self.OpenIdConnectService.RefreshToken(
			json_data['refresh_token'],
			json_data['client_id'],
			json_data['client_secret'],
			json_data['scope'])

		if not token_id:
			return await self.token_error_response(request, "Request didn't validate in Service.refresh_token")

		response = {
			"access_token": self.OpenIdConnectService.get_access_token(token_id),
			"token_type": "Bearer",
			"refresh_token": self.OpenIdConnectService.get_refresh_token(token_id),
			"expires_in": 3600,  # TODO: get this from session object
			"token_id": token_id,
		}

		return asab.web.rest.json_response(request, response, headers={
			'Cache-Control': 'no-store',
			'Pragma': 'no-cache',
		})


	async def token_error_response(self, request, error_description):
		"""
		3.1.3.4.  Token Error Response
		"""

		response = {
			"error": "invalid_request",
			"error_description": error_description
		}

		return asab.web.rest.json_response(request, response, headers={
			'Cache-Control': 'no-store',
			'Pragma': 'no-cache',
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
