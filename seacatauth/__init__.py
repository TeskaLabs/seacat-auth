import asab
import logging

from .app import SeaCatAuthApplication


asab.Config.add_defaults({
	"general": {
		# Absolute URL of the server where Seacat Auth API is available.
		# Used for deriving callback URLs, issuer IDs (OAuth, WebAuthn, ...).
		# For full feature availability, the use of HTTPS and a proper domain name is recommended.
		# Defaults to "http://localhost", which can be overwritten by PUBLIC_SERVER_URL environment variable.
		"public_url": "",

		# URL prefix of public Seacat Auth API
		# The URL can be either absolute, or relative to the "public_url" above.
		"public_seacat_auth_base_url": "api/seacat-auth/",

		# URL prefix of public OpenID Connect API
		# The URL can be either absolute, or relative to the "public_url" above.
		"public_openidconnect_base_url": "api/",

		# Auth web UI base URL lets the app know where the auth web UI is served to the public.
		# It is used for building login and password reset URIs.
		# The domain name is extracted for cookie and authentication purposes.
		# The URL can be either absolute, or relative to the "public_url" above.
		"auth_webui_base_url": "auth/",
	},

	# Admin API (non-public)
	"web": {
		"listen": "8900",  # Well-known port
	},

	# Auth API (public)
	"web:public": {
		"listen": "3081",  # Well-known port
	},

	"seacatauth": {
		"private_key": "",
	},

	"openidconnect": {
		"bearer_realm": "asab",
		"auth_code_timeout": "60 s",
	},

	"seacatauth:client": {
		# How long until the secret expires.
		# Set to "0" to disable the expiration.
		"client_secret_expiration": "0",

		# Validity period of local client metadata cache.
		# Set to "0" to disable cache.
		"cache_expiration": "30 s",
	},

	"seacatauth:cookie": {
		"name": "SeaCatSCI",

		"secure": "yes",

		# Specifies the domain scope where the cookie is valid
		# Leave empty unless necessary
		"domain": "",

		# Validity period of stored Redirect URIs
		"redirect_timeout": "60 s",

		# Length of the `state` string generated by the Redirect URI storage
		"redirect_state_length": "16",
	},

	"seacat:api": {
		# Specifies if non-public endpoints require authentication
		"require_authentication": "yes",

		# DEV ONLY!
		# Allow authentication via access token
		# This imposes the risk of the access token being misused by 3rd party app (user impersonation)
		"_allow_access_token_auth": "no",
	},

	"seacatauth:provisioning": {
		# Specifies which environment variable will activate provisioning mode when set to true
		"env_variable_name": "SEACAT_AUTH_PROVISIONING",
		"provisioning_config_file": "",
	},

	"seacatauth:credentials": {
		# Policy file specifies what attributes are used in user creation, registration and updating
		"policy_file": "",

		# Specify what attributes are used in locating credentials (if supported by the respective provider)
		# Attributes may be specified with a ":ignorecase" modifier for case-insensitive searching
		"ident_fields": "username:ignorecase email:ignorecase",
	},

	"seacatauth:tenant": {
		# Additional characters to be allowed in tenant IDs besides lowercase letters and numbers
		"additional_allowed_id_characters": "",
	},

	"seacatauth:registration": {
		# How long until invitation expires
		"expiration": "3d",

		# Use E2E encryption for registration form
		"enable_encryption": "no",

		# Allow people to register without an invitation
		"enable_self_registration": "no",
	},

	"seacatauth:communication": {
		"default_locale": "en",
		"template_path": "./etc/message_templates"
	},

	"seacatauth:otp": {
		# Issuer name appears as the name of the secret in the user 2FA app
		# Defaults to the hostname of auth webUI if left empty
		"issuer": "",
		# Maximum time between generating a TOTP secret and activating it
		"registration_timeout": "5 m"
	},

	"seacatauth:webauthn": {
		"relying_party_name": "SeaCat Auth",

		"challenge_timeout": "1 m"
	},

	"seacatauth:authentication": {
		# Path to JSON file which configures login descriptors and methods
		"descriptor_file": "",
		# "descriptor_file": "/conf/login-descriptors.json",

		# Whitespace-separated list of field names that will be passed to the credential provider
		# locate() method if supplied in login prologue request body `qs` parameter
		"custom_login_parameters": "",

		# Login attempts before login session is invalidated
		"login_attempts": 10,

		# Max login session duration
		"login_session_expiration": "5 m",

		# Force the user to log in using a second factor
		# Space-separated list of factor types of which the user must have at least one
		# Leave empty to disable second factor enforcement
		# Available factor types: "totp", "smscode"
		"enforce_factors": ""
	},

	"seacatauth:session": {
		# Root session expiration, also works as the default value for client sessions
		"expiration": "4 h",

		# Anonymous session expiration
		# By default it is the same as root session expiration
		"anonymous_expiration": "",

		# Touch extension specifies the timespan by which sessions are extended when session activity is detected
		# It can be either
		#   - specified relatively as a ratio of the original expiration (float between 0 and 1)
		#   - specified as absolute duration (float followed by a time unit, e.g. "40m", "5h", "3.5 d")
		# Relative extension example:
		#   A 3-hour session with touch_extension of "0.5" is created.
		#   Every time introspection happens, the expiration is postponed to CURRENT TIME + 1.5 hours (0.5*3 hours).
		# Absolute extension example:
		#   A 3-hour session with touch_extension of "20m" is created.
		#   Every time introspection happens, the expiration is postponed to CURRENT TIME + 20 minutes.
		"touch_extension": "0.5",

		# Specifies how often session can be touched to indicate their activity
		"touch_cooldown": "60 s",

		# Maximum session age, beyond which the session cannot be extended
		"maximum_age": "7 d",

		# Algorithmic sessions cache data about tenant and resource authorization.
		# This option sets the validity period of that data.
		"algo_cache_expiration": "3 m",
	},

	"seacatauth:password": {
		# Timeout for password reset requests
		"password_reset_expiration": "3 d",
	},

	"seacatauth:batman": {
		# Key used for generating Basic auth passwords
		"password_key": "",
	},
})

AuditLogger = logging.getLogger("AUDIT")

__all__ = [
	"SeaCatAuthApplication"
]
