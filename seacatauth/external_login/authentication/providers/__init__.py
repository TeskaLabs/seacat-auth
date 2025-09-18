from .abc import ExternalAuthProviderABC
from .oauth2 import OAuth2AuthProvider
from .github import GitHubOAuth2AuthProvider
from .google import GoogleOAuth2AuthProvider
from .office365 import Office365OAuth2AuthProvider
from .mojeid import MojeIDOAuth2AuthProvider
from .facebook import FacebookOAuth2AuthProvider
from .appleid import AppleIDOAuth2AuthProvider
from .saml2 import Saml2IdentityProvider


def create_provider(authn_handler, section):
	parts = section.split(":", 1)
	if len(parts) != 2 or parts[0] != "seacatauth":
		return None

	provider_type = parts[1]
	if provider_type == "oauth2:github":
		return GitHubOAuth2AuthProvider(authn_handler, section)
	if provider_type == "oauth2:google":
		return GoogleOAuth2AuthProvider(authn_handler, section)
	if provider_type == "oauth2:office365":
		return Office365OAuth2AuthProvider(authn_handler, section)
	if provider_type == "oauth2:mojeid":
		return MojeIDOAuth2AuthProvider(authn_handler, section)
	if provider_type == "oauth2:facebook":
		return FacebookOAuth2AuthProvider(authn_handler, section)
	if provider_type == "oauth2:appleid":
		return AppleIDOAuth2AuthProvider(authn_handler, section)
	if provider_type.startswith("oauth2:"):
		return OAuth2AuthProvider(authn_handler, section)
	if provider_type.startswith("saml2:"):
		return Saml2IdentityProvider(authn_handler, section)

	# Backward compatibility for old provider type names
	if provider_type == "github":
		return GitHubOAuth2AuthProvider(authn_handler, section)
	if provider_type == "google":
		return GoogleOAuth2AuthProvider(authn_handler, section)
	if provider_type == "office365":
		return Office365OAuth2AuthProvider(authn_handler, section)
	if provider_type == "mojeid":
		return MojeIDOAuth2AuthProvider(authn_handler, section)
	if provider_type == "facebook":
		return FacebookOAuth2AuthProvider(authn_handler, section)
	if provider_type == "appleid":
		return AppleIDOAuth2AuthProvider(authn_handler, section)

	return None


__all__ = [
	"ExternalAuthProviderABC",
	"OAuth2AuthProvider",
	"Saml2IdentityProvider",
	"GitHubOAuth2AuthProvider",
	"GoogleOAuth2AuthProvider",
	"Office365OAuth2AuthProvider",
	"MojeIDOAuth2AuthProvider",
	"FacebookOAuth2AuthProvider",
	"AppleIDOAuth2AuthProvider",
	"create_provider",
]
