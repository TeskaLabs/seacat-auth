import re
import time
import base64
import secrets
import logging

import asab

import aiohttp.web

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


	def __init__(self, app, service_name='seacatauth.OpenIdConnectService'):
		super().__init__(app, service_name)
		self.SessionService = app.get_service('seacatauth.SessionService')
		self.BearerRealm = asab.Config.get("openidconnect", "bearer_realm")

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
