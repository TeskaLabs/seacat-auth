from .oauth2 import OAuth2AuthProvider


class Office365OAuth2AuthProvider(OAuth2AuthProvider):
	"""
	This app must be first registered at Azure Active Directory:
	https://portal.azure.com

	Seacat Auth external login callback endpoint (/public/ext-login/callback) must be allowed as a redirect URIs
	in the OAuth client settings at the external login account provider.
	The full callback URL is canonically in the following format:
	https://{my_domain}/api/seacat-auth/public/ext-login/callback
	"""

	Type = "office365"
	ConfigDefaults = {
		"issuer": "https://login.microsoftonline.com/{tenant_id}/v2.0",
		"discovery_uri": "https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration",
		"jwks_uri": "https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
		"authorization_endpoint": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
		"token_endpoint": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
		"tenant_id": "",
		"scope": "openid",
		"label": "Office365",
	}

	def __init__(self, external_authentication_svc, config_section_name):
		super().__init__(external_authentication_svc, config_section_name)
		self.TenantID = self.Config.get("tenant_id")
		assert self.TenantID not in (None, "")

		self.Issuer = self.Issuer.format(tenant_id=self.TenantID)
		self.AuthorizationEndpoint = self.AuthorizationEndpoint.format(tenant_id=self.TenantID)
		self.JwksUri = self.JwksUri.format(tenant_id=self.TenantID)
		self.TokenEndpoint = self.TokenEndpoint.format(tenant_id=self.TenantID)
