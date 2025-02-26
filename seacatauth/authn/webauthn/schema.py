REGISTER_WEBAUTHN_CREDENTIAL = {
	"type": "object",
	"required": [
		"id",
		"rawId",
		"response",
		"type",
	],
	"properties": {
		"id": {
			# Credentials ID
			"type": "string"
		},
		"rawId": {
			# The ID again, but in binary form
			"type": "string"
		},
		"response": {
			# The actual WebAuthn login data
			"type": "object",
			"required": [
				"clientDataJSON",
				"attestationObject",
			],
			"properties": {
				"clientDataJSON": {"type": "string"},
				"attestationObject": {"type": "string"},
			}
		},
		"type": {
			"type": "string",
			"enum": ["public-key"],
		},
	}
}


UPDATE_WEBAUTHN_CREDENTIAL = {
	"type": "object",
	"required": [
		"name",
	],
	"properties": {
		"name": {
			"type": "string",
			"minLength": 3,
			"maxLength": 128,
		},
	}
}
