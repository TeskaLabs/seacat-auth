from .generic import GenericOAuth2Login


class GoogleOAuth2Login(GenericOAuth2Login):
	"""
	This app must be first registered at Google Cloud:
	https://console.cloud.google.com/apis/credentials

	Seacat Auth external login callback endpoint (/public/ext-login/callback) must be allowed as a redirect URIs
	in the OAuth client settings at the external login account provider.
	The full callback URL is canonically in the following format:
	https://{my_domain}/api/seacat-auth/public/ext-login/callback
	"""
	Type = "google"
	ConfigDefaults = {
		"issuer": "accounts.google.com",  # !! Google's issuer does not exactly match the one stated in discovery data
		"discovery_uri": "https://accounts.google.com/.well-known/openid-configuration",
		"jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
		"authorization_endpoint": "https://accounts.google.com/o/oauth2/auth",
		"token_endpoint": "https://accounts.google.com/o/oauth2/token",
		"scope": "openid profile email",
		"label": "Google",
	}
