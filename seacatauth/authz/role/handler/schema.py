CREATE_ROLE = {
	"type": "object",
	"additionalProperties": False,
	"properties": {
		"label": {"type": "string"},
		"description": {"type": "string"},
		"propagated": {"type": "boolean"},
		"resources": {
			"type": "array",
			"items": {"type": "string"},
		},
	}
}

UPDATE_ROLE = {
	"type": "object",
	"additionalProperties": False,
	"properties": {
		"label": {"type": "string"},
		"description": {"type": "string"},
		"add": {
			"type": "array",
			"items": {"type": "string"},
		},
		"del": {
			"type": "array",
			"items": {"type": "string"},
		},
		"set": {
			"type": "array",
			"items": {"type": "string"},
		},
	}
}

SET_CREDENTIALS_ROLES = {
	"type": "object",
	"properties": {
		"roles": {
			"type": "array",
			"items": {"type": "string"}
		}
	}
}

BATCH_GET_CREDENTIALS_ROLES = {
	"type": "array",
	"description": "Credential IDs",
	"items": {"type": "string"}
}
