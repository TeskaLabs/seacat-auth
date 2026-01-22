import enum
import asab.web.auth


class ResourceId(enum.StrEnum):
	SUPERUSER = asab.web.auth.SUPERUSER_RESOURCE_ID
	IMPERSONATE = "authz:impersonate"
	ACCESS_ALL_TENANTS = "authz:tenant:access"

	CREDENTIALS_ACCESS = "seacat:credentials:access"
	CREDENTIALS_EDIT = "seacat:credentials:edit"

	TENANT_ACCESS = "seacat:tenant:access"
	TENANT_CREATE = "seacat:tenant:create"
	TENANT_EDIT = "seacat:tenant:edit"
	TENANT_DELETE = "seacat:tenant:delete"
	TENANT_ASSIGN = "seacat:tenant:assign"

	ROLE_ACCESS = "seacat:role:access"
	ROLE_EDIT = "seacat:role:edit"
	ROLE_ASSIGN = "seacat:role:assign"

	RESOURCE_ACCESS = "seacat:resource:access"
	RESOURCE_EDIT = "seacat:resource:edit"

	CLIENT_ACCESS = "seacat:client:access"
	CLIENT_EDIT = "seacat:client:edit"
	CLIENT_APIKEY_MANAGE = "seacat:client:apikey:manage"

	APIKEY_ACCESS = "seacat:apikey:access"
	APIKEY_MANAGE = "seacat:apikey:manage"

	SESSION_ACCESS = "seacat:session:access"
	SESSION_TERMINATE = "seacat:session:terminate"


class OAuth2:

	class TokenEndpointAuthMethod(enum.StrEnum):
		NONE = "none"
		CLIENT_SECRET_BASIC = "client_secret_basic"
		CLIENT_SECRET_POST = "client_secret_post"
		# CLIENT_SECRET_JWT = "client_secret_jwt"
		# PRIVATE_KEY_JWT = "client_secret_post"


	class GrantType(enum.StrEnum):
		AUTHORIZATION_CODE = "authorization_code"
		CLIENT_CREDENTIALS = "client_credentials"
		# IMPLICIT = "implicit"
		REFRESH_TOKEN = "refresh_token"


	class ResponseType(enum.StrEnum):
		CODE = "code"
		# ID_TOKEN = "id_token"
		# TOKEN = "token"


	class ResponseMode(enum.StrEnum):
		QUERY = "query"
		FRAGMENT = "fragment"


	class ApplicationType(enum.StrEnum):
		WEB = "web"
		# NATIVE = "native"


	class RedirectUriValidationMethod(enum.StrEnum):
		FULL_MATCH = "full_match"
		PREFIX_MATCH = "prefix_match"
		NONE = "none"


	class CodeChallengeMethod(enum.StrEnum):
		# The methods must be ordered from the weakest to the strongest
		NONE = "none"
		PLAIN = "plain"
		S256 = "S256"

		@classmethod
		def is_stronger_or_equal(cls, a, b):
			"""
			Returns True if 'a' is stronger or equal to 'b'.
			"""
			for method in cls:
				# Whatever method encountered first is the weaker one
				if method == b:
					return True
				if method == a:
					return False


	class IdTokenSigningAlg(enum.StrEnum):
		# TODO: The algorithm RS256 MUST be included.
		#  (https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
		ES256 = "ES256"


	class SubjectType(enum.StrEnum):
		PUBLIC = "public"
		# pairwise = "pairwise"


	class Prompt(enum.StrEnum):
		NONE = "none"
		LOGIN = "login"
		SELECT_ACCOUNT = "select_account"
		# CONSENT = "consent"
		# CREATE = "create"


	class ClaimType(enum.StrEnum):
		NORMAL = "normal"
		# aggregated = "aggregated"
		# distributed = "distributed"
