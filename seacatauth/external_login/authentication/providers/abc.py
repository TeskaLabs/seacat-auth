import abc
import logging
import typing

import aiohttp.web
import asab


L = logging.getLogger(__name__)


class ExternalAuthProviderABC(abc.ABC, asab.Configurable):

	Type = None

	def __init__(self, external_authentication_svc, config_section_name, config=None):
		super().__init__(config_section_name, config)

		_, provider_type = config_section_name.split(":", 1)
		if self.Type is None:
			# Infer type for generic providers
			self.Type = provider_type
		elif self.Type != provider_type:
			raise ValueError("Provider type mismatch: expected {!r}, got {!r}".format(self.Type, provider_type))

		# UI-friendly provider name for the login button etc.
		self.Label = self.Config.get("label") or self.Type

		self.ExternalAuthenticationService = external_authentication_svc
		self.CallbackUrl = self.ExternalAuthenticationService.CallbackUrlTemplate.format(provider_type=self.Type)


	async def initialize(self, app):
		pass


	async def prepare_auth_request(self, state: dict, **kwargs) -> typing.Tuple[dict, aiohttp.web.Response]:
		"""
		Prepare an authentication request. This typically involves redirecting the user to the external
		login provider's authentication/authorization endpoint.

		Args:
			state: A dictionary to hold state information that can be used later in the authentication response.

		Returns:
			A tuple containing the updated state dictionary and an aiohttp.web.Response object
			(for example, a redirect response to the external provider).
		"""
		raise NotImplementedError()


	async def process_auth_callback(self, request: aiohttp.web.Request, payload: dict, state: dict, **kwargs) -> dict:
		"""
		Process the authentication response from the external login provider.
		This typically involves validating the response, extracting user information, and returning it
		in a structured format.

		Args:
			request: The aiohttp.web.Request object containing the authentication response from the external provider.
			payload: A dictionary containing the request payload (usually the POST body) received from the external provider.
			state: A dictionary containing state information that was set during the authentication request.

		Returns:
			A dictionary containing user information and any relevant tokens or claims.
		"""
		raise NotImplementedError()


	def acr_value(self) -> str:
		"""
		Authentication Context Class Reference (ACR)
		https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest

		OpenID Connect clients may use an ACR value in the authorization request to specifically request which external
		login provider should be used for End-User authentication.
		"""
		return "ext:{}".format(self.Type)
