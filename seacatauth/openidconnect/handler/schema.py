TOKEN_REVOKE = {
	"type": "object",
	"required": ["token"],
	"properties": {
		"token": {"type": "string"},
		"token_type_hint": {"type": "string"},
	}
}
