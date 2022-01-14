from .generic import GenericOAuth2Login


class MojeIDOAuth2Login(GenericOAuth2Login):
	"""
	Follow these implementation steps:
	https://www.mojeid.cz/dokumentace/html/ImplementacePodporyMojeid/OpenidConnect/PrehledKroku.html

	The following Redirect URIs must be allowed in MojeID service settings:
	https://{my_domain}/seacat_auth/public/ext-login/mojeid
	https://{my_domain}/seacat_auth/public/ext-login-add/mojeid
	"""
	Type = "mojeid"
	ConfigDefaults = {
		"authorize_uri": "https://mojeid.cz/oidc/authorization/",
		# "authorize_uri": "https://mojeid.cz/oidc/authorization/",  # test environment
		"access_token_uri": "https://mojeid.cz/oidc/token/",
		# "access_token_uri": "https://mojeid.cz/oidc/token/",       # test environment
		"scope": "openid email phone",
		"label": "Sign in with MojeID",
	}

	# TODO: MojeID provides extensive settings for encryption algorithms and other features.
	#   We might want to support some of that.
