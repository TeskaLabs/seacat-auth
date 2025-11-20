import logging
import asab.web.rest
import asab.web.auth
import asab.web.tenant

from .. import OpenIdConnectService
from ...models.const import OAuth2


L = logging.getLogger(__name__)


class DiscoveryHandler(object):
	"""
	OAuth 2.0 and OpenID Connect Server Discovery

	---
	tags: ["OAuth 2.0 / OpenID Connect"]
	"""

	def __init__(self, app, oidc_svc):
		self.App = app
		self.OpenIdConnectService: OpenIdConnectService = oidc_svc

		router_private = app.WebContainer.WebApp.router
		# The well-known locations are prescribed in
		# https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml
		router_private.add_get("/.well-known/oauth-authorization-server", self.oauth_authorization_server)
		router_private.add_get("/.well-known/openid-configuration", self.oidc_configuration)

		# Public endpoints
		router_public = app.PublicWebContainer.WebApp.router
		router_public.add_get("/.well-known/oauth-authorization-server", self.oauth_authorization_server)
		router_public.add_get("/.well-known/openid-configuration", self.oidc_configuration)


	@asab.web.auth.noauth
	@asab.web.tenant.allow_no_tenant
	async def oauth_authorization_server(self, request):
		"""
		OAuth 2.0 Authorization Server Metadata

		The OAuth 2.0 Authorization Server Metadata document is a JSON document that contains
		information about the OAuth 2.0 Authorization Server's configuration.

		https://datatracker.ietf.org/doc/html/rfc8414
		"""
		return asab.web.rest.json_response(request, self._oauth_server_metadata())


	@asab.web.auth.noauth
	@asab.web.tenant.allow_no_tenant
	async def oidc_configuration(self, request):
		"""
		OpenID Connect Provider Metadata

		The OpenID Connect Provider Metadata document is a JSON document that contains
		information about the OpenID Connect Provider's configuration.

		https://openid.net/specs/openid-connect-discovery-1_0.html
		"""
		return asab.web.rest.json_response(request, self._oidc_server_metadata())


	def _oauth_server_metadata(self):
		return {
			"issuer": self.OpenIdConnectService.Issuer,
			"authorization_endpoint": "{}{}".format(
				self.OpenIdConnectService.PublicApiBaseUrl, self.OpenIdConnectService.AuthorizePath.lstrip("/")),
			"token_endpoint": "{}{}".format(
				self.OpenIdConnectService.PublicApiBaseUrl, self.OpenIdConnectService.TokenPath.lstrip("/")),
			"jwks_uri": "{}{}".format(
				self.OpenIdConnectService.PublicApiBaseUrl, self.OpenIdConnectService.JwksPath.lstrip("/")),
			# "registration_endpoint"
			#       URL of the authorization server's OAuth 2.0 Dynamic
			#       Client Registration endpoint [RFC7591].
			"scopes_supported": [
				"openid", "profile", "email", "phone",
				"cookie", "batman", "anonymous", "impersonate:<credentials_id>", "tenant:<tenant_id>"],
			"response_types_supported": list(OAuth2.ResponseType),
			"response_modes_supported": list(OAuth2.ResponseMode),
			"grant_types_supported": list(OAuth2.GrantType),
			"token_endpoint_auth_methods_supported": list(OAuth2.TokenEndpointAuthMethod),
			"id_token_signing_alg_values_supported": list(OAuth2.IdTokenSigningAlg),
			"service_documentation": "https://docs.teskalabs.com/seacat-auth",
			"ui_locales_supported": ["en-US", "cs-CZ"],
			# "op_policy_uri"  # URL that the authorization server provides to the
			#       person registering the client to read about the authorization
			#       server's requirements on how the client can use the data provided
			#       by the authorization server.
			# "op_tos_uri"  # URL that the authorization server provides to the
			#       person registering the client to read about the authorization
			#       server's terms of service.
			"revocation_endpoint": "{}{}".format(
				self.OpenIdConnectService.PublicApiBaseUrl, self.OpenIdConnectService.TokenRevokePath),
			# "revocation_endpoint_auth_methods_supported"
			#       JSON array containing a list of client authentication
			#       methods supported by this revocation endpoint.
			# "revocation_endpoint_auth_signing_alg_values_supported"
			#       JSON array containing a list of the JWS signing
			#       algorithms ("alg" values) supported by the revocation endpoint for
			#       the signature on the JWT [JWT] used to authenticate the client at
			#       the revocation endpoint for the "private_key_jwt" and
			#       "client_secret_jwt" authentication methods.
			# "introspection_endpoint"
			#       URL of the authorization server's OAuth 2.0
			#       introspection endpoint [RFC7662].
			# "introspection_endpoint_auth_methods_supported"
			#       JSON array containing a list of client authentication
			#       methods supported by this introspection endpoint.
			# "introspection_endpoint_auth_signing_alg_values_supported"
			#       JSON array containing a list of the JWS signing
			#       algorithms ("alg" values) supported by the introspection endpoint
			#       for the signature on the JWT [JWT] used to authenticate the client
			#       at the introspection endpoint for the "private_key_jwt" and
			#       "client_secret_jwt" authentication methods.
			"code_challenge_methods_supported": list(OAuth2.CodeChallengeMethod),
		}


	def _oidc_server_metadata(self):
		data = self._oauth_server_metadata()
		data.update({
			"userinfo_endpoint": "{}{}".format(
				self.OpenIdConnectService.PublicApiBaseUrl, self.OpenIdConnectService.UserInfoPath.lstrip("/")),
			"subject_types_supported": list(OAuth2.SubjectType),
			"claims_supported": [
				"sub", "iss", "exp", "iat", "aud", "azp",
				"preferred_username", "email", "phone_number",
				"sid", "psid", "track_id",
				"resources", "tenants", "impersonator_sid", "impersonator_cid", "anonymous"],
			"end_session_endpoint": "{}{}".format(
				self.OpenIdConnectService.PublicApiBaseUrl, self.OpenIdConnectService.EndSessionPath),
			"claim_types_supported": list(OAuth2.ClaimType),
		})
		return data
