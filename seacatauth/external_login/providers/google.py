from .generic import GenericOAuth2Login


class GoogleOAuth2Login(GenericOAuth2Login):
	"""
	This app must be first registered at Google Cloud:
	https://console.cloud.google.com/apis/credentials

	The following Redirect URIs must be allowed in the Google OAuth2:
	https://{my_domain}/seacat_auth/public/ext-login/google
	https://{my_domain}/seacat_auth/public/ext-login-add/google
	"""
	Type = "google"
	ConfigDefaults = {
		"issuer": "accounts.google.com",  # !! Google's issuer does not exactly match the one stated in discovery data
		"discovery_uri": "https://accounts.google.com/.well-known/openid-configuration",
		"jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
		"authorization_endpoint": "https://accounts.google.com/o/oauth2/auth",
		"token_endpoint": "https://accounts.google.com/o/oauth2/token",
		"scope": "openid profile email",
		"label": "Sign in with Google",
	}
