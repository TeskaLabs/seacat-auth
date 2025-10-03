def create_provider(authn_handler, section):
	parts = section.split(":", 1)
	if len(parts) != 2 or parts[0] != "seacatauth":
		return None

	provider_type = parts[1]
	if provider_type == "oauth2:github":
		from .github import GitHubOAuth2AuthProvider
		return GitHubOAuth2AuthProvider(authn_handler, section)
	if provider_type == "oauth2:google":
		from .google import GoogleOAuth2AuthProvider
		return GoogleOAuth2AuthProvider(authn_handler, section)
	if provider_type == "oauth2:office365":
		from .office365 import Office365OAuth2AuthProvider
		return Office365OAuth2AuthProvider(authn_handler, section)
	if provider_type == "oauth2:mojeid":
		from .mojeid import MojeIDOAuth2AuthProvider
		return MojeIDOAuth2AuthProvider(authn_handler, section)
	if provider_type == "oauth2:facebook":
		from .facebook import FacebookOAuth2AuthProvider
		return FacebookOAuth2AuthProvider(authn_handler, section)
	if provider_type == "oauth2:appleid":
		from .appleid import AppleIDOAuth2AuthProvider
		return AppleIDOAuth2AuthProvider(authn_handler, section)
	if provider_type.startswith("oauth2:"):
		from .oauth2 import OAuth2AuthProvider
		return OAuth2AuthProvider(authn_handler, section)
	if provider_type.startswith("saml:"):
		from .saml import SamlAuthProvider
		return SamlAuthProvider(authn_handler, section)

	# Backward compatibility for old provider type names
	if provider_type == "github":
		from .github import GitHubOAuth2AuthProvider
		return GitHubOAuth2AuthProvider(authn_handler, section)
	if provider_type == "google":
		from .google import GoogleOAuth2AuthProvider
		return GoogleOAuth2AuthProvider(authn_handler, section)
	if provider_type == "office365":
		from .office365 import Office365OAuth2AuthProvider
		return Office365OAuth2AuthProvider(authn_handler, section)
	if provider_type == "mojeid":
		from .mojeid import MojeIDOAuth2AuthProvider
		return MojeIDOAuth2AuthProvider(authn_handler, section)
	if provider_type == "facebook":
		from .facebook import FacebookOAuth2AuthProvider
		return FacebookOAuth2AuthProvider(authn_handler, section)
	if provider_type == "appleid":
		from .appleid import AppleIDOAuth2AuthProvider
		return AppleIDOAuth2AuthProvider(authn_handler, section)

	return None


__all__ = [
	"create_provider",
]
