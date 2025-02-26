# https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
# TODO: Supported OAuth/OIDC param values should be managed by the OpenIdConnect module, not Client.
GRANT_TYPES = [
	"authorization_code",
	# "implicit",
	# "refresh_token"
]

RESPONSE_TYPES = [
	"code",
	# "id_token",
	# "token"
]

APPLICATION_TYPES = [
	"web",
	# "native"
]

TOKEN_ENDPOINT_AUTH_METHODS = [
	"none",
	"client_secret_basic",
	"client_secret_post",
	# "client_secret_jwt",
	# "private_key_jwt"
]

REDIRECT_URI_VALIDATION_METHODS = [
	"full_match",
	"prefix_match",
	"none",
]

CLIENT_METADATA_SCHEMA = {
	# The order of the properties is preserved in the UI form
	"preferred_client_id": {
		"type": "string",
		"pattern": "^[-_a-zA-Z0-9]{4,64}$",
		"description": "(Non-canonical) Preferred client ID."},
	"client_name": {  # Can have language tags (e.g. "client_name#cs")
		"type": "string",
		"description": "Name of the Client to be presented to the End-User."},
	"client_uri": {  # Can have language tags
		"type": "string",
		"description": "URL of the home page of the Client."},
	"cookie_domain": {  # NON-CANONICAL
		"type": "string",
		"pattern": "^[a-z0-9\\.-]{1,61}\\.[a-z]{2,}$|^$",
		"description":
			"Domain of the client cookie. Defaults to the application's global cookie domain."},
	"cookie_webhook_uri": {  # NON-CANONICAL
		"type": "string",
		"description":
			"Webhook URI for setting additional custom cookies at the cookie entrypoint. "
			"It must be a back-channel URI and it must accept a JSON PUT request and "
			"respond with a JSON object of cookies to set."},
	"cookie_entry_uri": {  # NON-CANONICAL
		"type": "string",
		"description":
			"Public URI of the client's cookie entrypoint."},
	"redirect_uris": {
		"type": "array",
		"description": "Array of Redirection URI values used by the Client.",
		"items": {"type": "string"}},
	#  "contacts": {},
	# "custom_data": {  # NON-CANONICAL
	# 	"type": "object", "description": "(Non-canonical) Additional client data."},
	# "logout_uri": {  # NON-CANONICAL
	# 	"type": "string", "description": "(Non-canonical) URI that will be called on session logout."},
	"application_type": {
		"type": "string",
		"description": "Kind of the application. The default, if omitted, is `web`.",
		"enum": APPLICATION_TYPES},
	"response_types": {
		"type": "array",
		"description":
			"JSON array containing a list of the OAuth 2.0 response_type values "
			"that the Client is declaring that it will restrict itself to using. "
			"If omitted, the default is that the Client will use only the `code` Response Type.",
		"items": {
			"type": "string",
			"enum": RESPONSE_TYPES}},
	"grant_types": {
		"type": "array",
		"description":
			"JSON array containing a list of the OAuth 2.0 Grant Types "
			"that the Client is declaring that it will restrict itself to using. "
			"If omitted, the default is that the Client will use only the `authorization_code` Grant Type.",
		"items": {
			"type": "string",
			"enum": GRANT_TYPES}},
	# "logo_uri": {},  # Can have language tags
	# "policy_uri": {},  # Can have language tags
	# "tos_uri": {},  # Can have language tags
	# "jwks_uri": {},
	# "jwks": {},
	# "sector_identifier_uri": {},
	# "subject_type": {},
	# "id_token_signed_response_alg": {},
	# "id_token_encrypted_response_alg": {},
	# "id_token_encrypted_response_enc": {},
	# "userinfo_signed_response_alg": {},
	# "userinfo_encrypted_response_alg": {},
	# "userinfo_encrypted_response_enc": {},
	# "request_object_signing_alg": {},
	# "request_object_encryption_alg": {},
	# "request_object_encryption_enc": {},
	"token_endpoint_auth_method": {
		"type": "string",
		"description":
			"Requested Client Authentication method for the Token Endpoint. "
			"If omitted, the default is `none`.",
		"enum": TOKEN_ENDPOINT_AUTH_METHODS},
	# "token_endpoint_auth_signing_alg": {},
	# "default_max_age": {},
	# "require_auth_time": {},
	# "default_acr_values": {},
	# "initiate_login_uri": {},
	# "request_uris": {},
	"code_challenge_method": {
		"type": "string",
		"description":
			"Code Challenge Method (PKCE) that the Client will be required to use at the Authorize Endpoint. "
			"The default, if omitted, is `none`.",
		"enum": ["none", "plain", "S256"]},
	"authorize_uri": {  # NON-CANONICAL
		"type": "string",
		"description":
			"URL of OAuth authorize endpoint. Useful when logging in from different than the default domain."},
	"login_uri": {  # NON-CANONICAL
		"type": "string",
		"description": "URL of preferred login page."},
	"authorize_anonymous_users": {  # NON-CANONICAL
		"type": "boolean",
		"description": "Allow authorize requests with anonymous users."},
	"anonymous_cid": {  # NON-CANONICAL
		"type": "string",
		"description": "ID of credentials that is used for authenticating anonymous sessions."},
	"session_expiration": {  # NON-CANONICAL
		"oneOf": [{"type": "string"}, {"type": "number"}],
		"description":
			"Client session expiration. The value can be either the number of seconds "
			"or a time-unit string such as '4 h' or '3 d'."},
	"redirect_uri_validation_method": {  # NON-CANONICAL
		"type": "string",
		"description":
			"Specifies the method how the redirect URI used in authorization requests is validated. "
			"The default value is 'full_match', in which the requested redirect URI must fully match "
			"one of the registered URIs.",
		"enum": REDIRECT_URI_VALIDATION_METHODS},
}

REGISTER_CLIENT = {
	"type": "object",
	"required": ["redirect_uris", "client_name"],
	"additionalProperties": False,
	"properties": CLIENT_METADATA_SCHEMA,
	# "patternProperties": {
	#   # Language-specific metadata with RFC 5646 language tags
	# 	"^client_name#[-a-zA-Z0-9]+$": {"type": "string"},
	# 	"^logo_uri#[-a-zA-Z0-9]+$": {"type": "string"},
	# 	"^client_uri#[-a-zA-Z0-9]+$": {"type": "string"},
	# 	"^policy_uri#[-a-zA-Z0-9]+$": {"type": "string"},
	# 	"^tos_uri#[-a-zA-Z0-9]+$": {"type": "string"},
	# }
}

UPDATE_CLIENT = {
	"type": "object",
	"additionalProperties": False,
	"properties": CLIENT_METADATA_SCHEMA
}

CLIENT_TEMPLATES = {
	"Public web application": {
		"application_type": "web",
		"token_endpoint_auth_method": "none",
		"grant_types": ["authorization_code"],
		"response_types": ["code"]},
	# "Public mobile application": {
	# 	"application_type": "native",
	# 	"token_endpoint_auth_method": "none",
	# 	"grant_types": ["authorization_code"],
	# 	"response_types": ["code"]},
	"Custom": {},
}
