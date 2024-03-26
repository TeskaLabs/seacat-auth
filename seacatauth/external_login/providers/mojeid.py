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
		"issuer": "https://mojeid.cz",
		"discovery_uri": "https://mojeid.cz/.well-known/openid-configuration",
		"jwks_uri": "https://mojeid.cz/oidc/key.jwk",
		"authorization_endpoint": "https://mojeid.cz/oidc/authorization/",
		"token_endpoint": "https://mojeid.cz/oidc/token/",
		"scope": "openid email phone",
		"label": "MojeID",
	}

	# TODO: MojeID provides extensive settings for encryption algorithms and other features.
	#   We might want to support some of that.
