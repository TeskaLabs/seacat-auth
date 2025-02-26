JWK_PARAMS = {
	"crv": {"type": "string"},
	"ext": {"type": "boolean"},
	"key_ops": {"type": "array", "items": {"type": "string"}},
	"kty": {"type": "string"},
	"x": {"type": "string"},
	"y": {"type": "string"}
}

LOGIN_PROLOGUE = {
	"type": "object",
	"required": ["ident", *JWK_PARAMS.keys()],
	"properties": {
		"ident": {
			"type": "string",
			"description": "Value (usually email or username) used for locating credentials to be used for login."},
		"qs": {
			"type": "string",
			"description":
				"Optional extra parameters used for locating credentials. "
				"Allowed parameter names must be listed in `[seacatauth:authentication] custom_login_parameters` "
				"in the app configuration."},
		**JWK_PARAMS
	}
}

IMPERSONATE = {
	"type": "object",
	"required": ["credentials_id"],
	"properties": {
		"credentials_id": {
			"type": "string",
			"description": "Credentials ID of the impersonation target."},
		"expiration": {
			"oneOf": [{"type": "string"}, {"type": "number"}],
			"description":
				"Expiration of the impersonated session. The value can be either the number of seconds "
				"or a time-unit string such as '4 h' or '3 d'."}},
	"example": {
		"credentials_id": "mongodb:default:abc123def456",
		"expiration": "5m"}
}
