import logging

import asab.web.rest

from .. import OpenIdConnectService

#

L = logging.getLogger(__name__)


#


class DiscoveryHandler(object):
	"""
	OpenID Connect Discovery

	https://openid.net/specs/openid-connect-discovery-1_0.html

	---
	tags: ["OAuth 2.0 / OpenID Connect"]
	"""

	def __init__(self, app, oidc_svc):
		self.App = app
		self.OpenIdConnectService: OpenIdConnectService = oidc_svc

		web_app = app.WebContainer.WebApp
		# The well-known location is prescribed in
		# https://www.rfc-editor.org/rfc/rfc8414#section-3
		web_app.router.add_get("/.well-known/openid-configuration", self.configuration)
		web_app.router.add_get("/openidconnect/configuration", self.configuration)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get("/.well-known/openid-configuration", self.configuration)
		web_app_public.router.add_get("/openidconnect/configuration", self.configuration)


	async def configuration(self, request):
		"""
		OpenID Connect Discovery

		OpenID Providers supporting Discovery MUST make a JSON document available at the path formed by
		concatenating the string /.well-known/openid-configuration to the Issuer.
		"""
		# TODO: Refactor. Extract all this data from OpenIdConnectService.
		data = {
			# REQUIRED
			"issuer": self.OpenIdConnectService.Issuer,
			"authorization_endpoint": self.OpenIdConnectService.authorization_endpoint_url(),
			"token_endpoint": self.OpenIdConnectService.token_endpoint_url(),
			# TODO: The algorithm RS256 MUST be included.
			#  (https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
			"id_token_signing_alg_values_supported": ["ES256"],
			"jwks_uri": "{}{}".format(
				self.OpenIdConnectService.PublicApiBaseUrl, self.OpenIdConnectService.JwksPath.lstrip("/")),
			"response_types_supported": ["code"],
			"subject_types_supported": ["public"],

			# RECOMMENDED
			"userinfo_endpoint": self.OpenIdConnectService.userinfo_endpoint_url(),
			# "registration_endpoint": "{}/public/client/register",  # TODO: Implement a PUBLIC client registration API
			"scopes_supported": [
				"openid", "profile", "email", "phone",
				"cookie", "batman", "anonymous", "impersonate:<credentials_id>", "tenant:<tenant_id>"],
			"claims_supported": [
				"sub", "iss", "exp", "iat", "aud", "azp",
				"preferred_username", "email", "phone_number",
				"sid", "psid", "track_id",
				"resources", "tenants", "impersonator_sid", "impersonator_cid", "anonymous"],

			# OPTIONAL
			"end_session_endpoint": "{}{}".format(
				self.OpenIdConnectService.PublicApiBaseUrl, self.OpenIdConnectService.EndSessionPath),
			"revocation_endpoint": "{}{}".format(
				self.OpenIdConnectService.PublicApiBaseUrl, self.OpenIdConnectService.TokenRevokePath),
			"grant_types_supported": ["authorization_code"],
			"token_endpoint_auth_methods_supported": ["none"],
			"prompt_values_supported": ["none", "login", "select_account"],
			"claim_types_supported": ["normal"],
			"service_documentation": "https://docs.teskalabs.com/seacat-auth",
			"ui_locales_supported": ["en-US", "cs-CZ"],

			# PKCE
			"code_challenge_methods_supported": ["plain", "S256"],
		}

		return asab.web.rest.json_response(request, data)
