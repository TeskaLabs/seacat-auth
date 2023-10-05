from .generic import GenericOAuth2Login


class Office365OAuth2Login(GenericOAuth2Login):
	"""
	This app must be first registered at Azure Active Directory:
	https://portal.azure.com

	The following Redirect URIs must be allowed in the Google OAuth2:
	https://{my_domain}/seacat_auth/public/ext-login/office365
	https://{my_domain}/seacat_auth/public/ext-login-add/office365
	"""
	Type = "office365"
	ConfigDefaults = {
		"issuer": "https://sts.windows.net/{tenant_id}",
		"discovery_uri": "https://sts.windows.net/{tenant_id}/.well-known/openid-configuration",
		# also available at "https://login.microsoftonline.com/{tenant_id}/.well-known/openid-configuration",
		"jwks_uri": "https://login.microsoftonline.com/common/discovery/keys",
		"authorization_endpoint": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
		"token_endpoint": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
		"tenant_id": "",
		"scope": "openid",
		"label": "Sign in with Office365",
	}

	def __init__(self, external_login_svc, config_section_name):
		super().__init__(external_login_svc, config_section_name)
		self.TenantID = self.Config.get("tenant_id")
		assert self.TenantID not in (None, "")

		self.Issuer = self.Issuer.format(tenant_id=self.TenantID)
		self.AuthorizationEndpoint = self.AuthorizationEndpoint.format(tenant_id=self.TenantID)
		self.TokenEndpoint = self.TokenEndpoint.format(tenant_id=self.TenantID)
