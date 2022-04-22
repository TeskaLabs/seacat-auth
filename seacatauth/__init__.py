from .app import SeaCatAuthApplication

import asab

asab.Config.add_defaults({
	"general": {
		"registration_encrypted": "false",

		# public base URL is used for behind reverse proxy deployment, for application, to be aware from what url is api served.
		# It is needed in oidc authorize handler, to give redirect uri back to itself when forwarding to login endpoint
		"public_api_base_url": "http://localhost:3000/api",

		# app base URL is used for behind reverse proxy deployment, for application, to be aware from what url seacat-auth-webui application is served
		# It is needed for app login endpoint and app reset pwd endpoints
		"auth_webui_base_url": "http://localhost:3000/auth",
	},

	"openidconnect": {
		"bearer_realm": "asab",
		"auth_code_timeout": "60 s",
	},

	"seacatauth:cookie": {
		"name": "SeaCatSCI",

		# Cookie domain specifies the domain scope where the cookie is valid
		# MUST NOT BE EMPTY!
		# NOTE:
		#   To fully work in all major browsers, cookie domain must contain at least two dots (requirement by Firefox).
		#   For example, "localhost" or ".com" may not work properly,
		#   but ".app.localhost" or ".example.com" should work fine.
		"domain": ""
	},

	"seacat:api": {
		# Specifies if non-public endpoints require authentication
		"require_authentication": "yes",

		# Specifies resource required for API access
		# If set to "DISABLED", no authorization is required
		"authorization_resource": "seacat:access"
	},

	"seacatauth:provisioning": {
		# Specifies which environment variable will activate provisioning mode when set to true
		"env_variable_name": "SEACAT_AUTH_PROVISIONING",
		"superuser_name": "superuser",
		"superrole_id": "*/provisioning-superrole",
		"credentials_provider_id": "provisioning",
		"tenant": "provisioning-tenant",
	},

	"seacatauth:credentials": {
		# Policy file specifies what attributes are used in user creation, registration and updating
		"policy_file": "",

		# Specify what attributes are used in locating credentials (if supported by the respective provider)
		# Attributes may be specified with a ":ignorecase" modifier for case-insensitive searching
		"ident_fields": "username:ignorecase email:ignorecase",
	},

	"seacatauth:communication": {
		"default_locale": "en",
		"app_name": "SeacatAuth",
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
		# Default session expiration in seconds
		"expiration": "4 h",

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

		# Maximum session age, beyond which the session cannot be extended
		"maximum_age": "7 d",

		# Key used for sensitive field encryption
		# MUST NOT BE EMPTY!
		"aes_key": ""
	},

	"seacatauth:password": {
		# Default expiration in "{float} {unit}" format
		"password_reset_expiration": "3 d",
	},
})

__all__ = [
	'SeaCatAuthApplication'
]
