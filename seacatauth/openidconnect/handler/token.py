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

from seacatauth.session import SessionAdapter

#

L = logging.getLogger(__name__)

#


class TokenHandler(object):

	def __init__(self, app, oidc_svc):
		self.OpenIdConnectService = oidc_svc
		self.SessionService = app.get_service('seacatauth.SessionService')
		self.CredentialsService = app.get_service('seacatauth.CredentialsService')

		web_app = app.WebContainer.WebApp
		web_app.router.add_post('/openidconnect/token', self.token_request)
		web_app.router.add_post('/openidconnect/token/revoke', self.token_revoke)
		web_app.router.add_post('/openidconnect/token/refresh', self.token_refresh)
		web_app.router.add_put('/openidconnect/token/validate', self.validate_id_token)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_post('/openidconnect/token', self.token_request)
		web_app_public.router.add_post('/openidconnect/token/revoke', self.token_revoke)
		web_app_public.router.add_post('/openidconnect/token/refresh', self.token_refresh)
		web_app_public.router.add_put('/openidconnect/token/validate', self.validate_id_token)


	async def token_request(self, request):
		data = await request.text()
		qs_data = dict(urllib.parse.parse_qsl(data))

		# 3.1.3.2.  Token Request Validation
		grant_type = qs_data.get('grant_type', '<missing>')

		if grant_type == 'authorization_code':
			return await self.token_request_authorization_code(request, qs_data)

		if grant_type == 'batman':
			# TODO: Call the batman service (when implemented)
			return await self.token_request_batman(request, qs_data)

		L.warning("Grant Type is not 'authorization_code' but '{}'".format(grant_type))
		return aiohttp.web.HTTPBadRequest()


	async def token_request_authorization_code(self, request, qs_data):
		"""
		https://openid.net/specs/openid-connect-core-1_0.html

		3.1.3.1.  Token Request

		Request contains query string such as:
		grant_type=authorization_code&code=foo-bar-code&redirect_uri=....

		"""

		# Ensure the Authorization Code was issued to the authenticated Client
		authorization_code = qs_data.get('code', '')
		if len(authorization_code) == 0:
			L.warning("Authorization Code not provided")
			return aiohttp.web.HTTPBadRequest()

		# Translate authorization code into session id
		# Verify that the Authorization Code has not been previously used (using `pop` operation)
		try:
			session_id = await self.OpenIdConnectService.pop_session_id_by_authorization_code(authorization_code)
		except KeyError:
			L.warning("Authorization code not found", struct_data={"code": authorization_code})
			return aiohttp.web.HTTPBadRequest()

		# Locate the session using session id
		try:
			session = await self.SessionService.get(session_id)
		except KeyError:
			L.error("Session not found", struct_data={"sid": session_id})
			return aiohttp.web.HTTPBadRequest()

		if session is None:
			L.warning("Authorization Code not valid")
			return aiohttp.web.HTTPBadRequest()

		# Check if the redirect URL is the same as the one in the authorization request
		# if authorization_request.get("redirect_uri") != qs_data.get('redirect_uri'):
		# 	return await self.token_error_response(request, "The redirect URL is not associated with the client.")

		headers = {
			'Cache-Control': 'no-store',
			'Pragma': 'no-cache',
		}

		expires_in = int((session.Session.Expiration - datetime.datetime.now(datetime.timezone.utc)).total_seconds())

		id_token = await self.OpenIdConnectService.build_id_token(session)

		# Save the ID token in the session object
		await self.SessionService.update_session(
			session_id,
			session_builders=[[(SessionAdapter.FN.OAuth2.IdToken, id_token.encode())]]
		)

		# 3.1.3.3.  Successful Token Response
		body = {
			"token_type": "Bearer",
			"scope": " ".join(session.OAuth2.Scope),
			"access_token": session.OAuth2.AccessToken,
			"refresh_token": session.OAuth2.RefreshToken,
			"id_token": id_token,
			"expires_in": expires_in,
		}

		return asab.web.rest.json_response(request, body, headers=headers)


	async def token_request_batman(self, request, qs_data):

		# Ensure the Authorization Code was issued to the authenticated Client
		# If possible, verify that the Authorization Code has not been previously used
		authorization_code = qs_data.get('code', '')
		if len(authorization_code) == 0:
			L.warning("Authorization Code not provided")
			return aiohttp.web.HTTPBadRequest()

		# Translate authorization code into session id
		try:
			session_id = await self.OpenIdConnectService.pop_session_id_by_authorization_code(authorization_code)
		except KeyError:
			L.warning("Authorization code not found", struct_data={"code": authorization_code})
			return aiohttp.web.HTTPBadRequest()

		# Locate the session using session id
		try:
			session = await self.SessionService.get(session_id)
		except KeyError:
			return aiohttp.web.HTTPBadRequest()

		if session is None:
			L.warning("Authorization Code not valid")
			return aiohttp.web.HTTPBadRequest()

		credentials = await self.CredentialsService.get(session.Credentials.Id)

		headers = {
			'Cache-Control': 'no-store',
			'Pragma': 'no-cache',
		}

		body = {
			"token_type": "Batman",
			"cid": session.Credentials.Id,
			"username": credentials['username'],
		}

		return asab.web.rest.json_response(request, body, headers=headers)


	@asab.web.rest.json_schema_handler({
		'type': 'object',
		'required': ['token'],
		'properties': {
			'token': {'type': 'string'},
			'token_type_hint': {'type': 'string'},
		}
	})
	async def token_revoke(self, request, *, json_data):
		# TODO: this is not implemented

		if not self.OpenIdConnectService.check_access_token(request.headers["Authorization"].split()[1]):
			raise aiohttp.web.HTTPForbidden(reason="User is not authenticated")

		"""
		https://tools.ietf.org/html/rfc7009

		2.1.  Revocation Request
		"""

		token_type_hint = json_data.get("token_type_hint")  # Optional `access_token` or `refresh_token`
		if token_type_hint:
			if token_type_hint == 'access_token':
				self.OpenIdConnectService.invalidate_access_token(json_data['token'])
			elif token_type_hint == 'refresh_token':
				self.OpenIdConnectService.invalidate_refresh_token(json_data['token'])
			else:
				return await self.token_error_response(request, "Unknown token_type_hint {}".format(token_type_hint))
		self.OpenIdConnectService.invalidate_token(json_data['token'])
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
		6.  Refreshing an Access token
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

