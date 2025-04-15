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


	class ApplicationType(enum.StrEnum):
		WEB = "web"
		# NATIVE = "native"


	class RedirectUriValidationMethod(enum.StrEnum):
		FULL_MATCH = "full_match"
		PREFIX_MATCH = "prefix_match"
		NONE = "none"


	class CodeChallengeMethod(enum.StrEnum):
		NONE = "none"
		PLAIN = "plain"
		S256 = "S256"


	class IdTokenSigningAlg(enum.StrEnum):
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
