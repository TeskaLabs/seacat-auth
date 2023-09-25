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
		"discovery_uri": "https://accounts.google.com/.well-known/openid-configuration",
		"authorize_uri": "https://accounts.google.com/o/oauth2/auth",
		"access_token_uri": "https://accounts.google.com/o/oauth2/token",
		"scope": "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email",
		"jwt_public_keys": "",  # For id_token validation
		"label": "Sign in with Google",
	}
