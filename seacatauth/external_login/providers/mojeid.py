from .generic import GenericOAuth2Login


class MojeIDOAuth2Login(GenericOAuth2Login):
	"""
	Follow these implementation steps:
	https://www.mojeid.cz/dokumentace/html/ImplementacePodporyMojeid/OpenidConnect/PrehledKroku.html

	Seacat Auth external login callback endpoint (/public/ext-login/callback) must be allowed as a redirect URIs
	in the OAuth client settings at the external login account provider.
	The full callback URL is canonically in the following format:
	https://{my_domain}/api/seacat-auth/public/ext-login/callback
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
