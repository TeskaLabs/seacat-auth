from .abc import ExternalIdentityProviderABC
from .oauth2 import OAuth2IdentityProvider
from .github import GitHubOAuth2IdentityProvider
from .google import GoogleOAuth2IdentityProvider
from .office365 import Office365OAuth2IdentityProvider
from .mojeid import MojeIDOAuth2IdentityProvider
from .facebook import FacebookOAuth2IdentityProvider
from .appleid import AppleIDOAuth2IdentityProvider
from .saml2 import Saml2IdentityProvider


def create_provider(authn_handler, section):
	parts = section.split(":", 1)
	if len(parts) != 2 or parts[0] != "seacatauth":
		return None

	provider_type = parts[1]
	if provider_type == "oauth2:github":
		return GitHubOAuth2IdentityProvider(authn_handler, section)
	if provider_type == "oauth2:google":
		return GoogleOAuth2IdentityProvider(authn_handler, section)
	if provider_type == "oauth2:office365":
		return Office365OAuth2IdentityProvider(authn_handler, section)
	if provider_type == "oauth2:mojeid":
		return MojeIDOAuth2IdentityProvider(authn_handler, section)
	if provider_type == "oauth2:facebook":
		return FacebookOAuth2IdentityProvider(authn_handler, section)
	if provider_type == "oauth2:appleid":
		return AppleIDOAuth2IdentityProvider(authn_handler, section)
	if provider_type.startswith("oauth2:"):
		return OAuth2IdentityProvider(authn_handler, section)
	if provider_type.startswith("saml2:"):
		return Saml2IdentityProvider(authn_handler, section)

	# Backward compatibility for old provider type names
	if provider_type == "github":
		return GitHubOAuth2IdentityProvider(authn_handler, section)
	if provider_type == "google":
		return GoogleOAuth2IdentityProvider(authn_handler, section)
	if provider_type == "office365":
		return Office365OAuth2IdentityProvider(authn_handler, section)
	if provider_type == "mojeid":
		return MojeIDOAuth2IdentityProvider(authn_handler, section)
	if provider_type == "facebook":
		return FacebookOAuth2IdentityProvider(authn_handler, section)
	if provider_type == "appleid":
		return AppleIDOAuth2IdentityProvider(authn_handler, section)

	return None


__all__ = [
	"ExternalIdentityProviderABC",
	"OAuth2IdentityProvider",
	"Saml2IdentityProvider",
	"GitHubOAuth2IdentityProvider",
	"GoogleOAuth2IdentityProvider",
	"Office365OAuth2IdentityProvider",
	"MojeIDOAuth2IdentityProvider",
	"FacebookOAuth2IdentityProvider",
	"AppleIDOAuth2IdentityProvider",
	"create_provider",
]
