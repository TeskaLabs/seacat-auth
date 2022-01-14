from .generic import GenericOAuth2Login
from .github import GitHubOAuth2Login
from .google import GoogleOAuth2Login
from .office365 import Office365OAuth2Login
from .mojeid import MojeIDOAuth2Login


def create_provider(authn_handler, section):
	if section.startswith("seacatauth:oauth2:"):
		return GenericOAuth2Login(authn_handler, section)
	if section == "seacatauth:github":
		return GitHubOAuth2Login(authn_handler, section)
	if section == "seacatauth:google":
		return GoogleOAuth2Login(authn_handler, section)
	if section == "seacatauth:office365":
		return Office365OAuth2Login(authn_handler, section)
	if section == "seacatauth:mojeid":
		return MojeIDOAuth2Login(authn_handler, section)
	return None


__all__ = [
	"GenericOAuth2Login",
	"GitHubOAuth2Login",
	"GoogleOAuth2Login",
	"Office365OAuth2Login",
	"MojeIDOAuth2Login",
	"create_provider",
]
