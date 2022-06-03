# TODO: Handle schema building systematically in a dedicated class
#   Connect with Policy class

# Based on Unix usernames
USERNAME_PATTERN = r"^[a-z_][a-z0-9_-]{0,31}$"

_FIELDS = {
	"username": {
		"type": "string",
		"description": "Username",
	},
	"email": {
		"type": "string",
		"description": "Email address",
		"anyOf": [
			{"format": "email"},
			{"const": ""},
		],
	},
	"phone": {
		"type": "string",
		"description": "Mobile number",
		"anyOf": [
			{"pattern": r"^\+?[0-9 ]+$"},
			{"const": ""},
		],
	},
	"data": {
		"type": "object",
		"description": "Custom data",
		"patternProperties": {
			"^[a-zA-Z][a-zA-Z0-9_-]{0,126}[a-zA-Z0-9]$": {"anyOf": [
				{"type": "string"},
				{"type": "number"},
				{"type": "boolean"},
				{"type": "null"},
			]}
		},
		"additionalProperties": False,
	},
	"suspended": {
		"type": "boolean",
		"description": "Is suspended?"
	},
	"password": {
		"type": "string",
		"description": "Password",
	},
	"passwordlink": {
		"type": "boolean",
		"description": "Send a link for password reset?",
	}
}

CREATE_CREDENTIALS = {
	"type": "object",
	"additionalProperties": False,
	"properties": {
		field: schema
		for field, schema in _FIELDS.items()
		if field in frozenset([
			"username",
			"email",
			"phone",
			"password",  # May be used for M2M credentials
			"passwordlink",
		])
	},
}

UPDATE_CREDENTIALS = {
	"type": "object",
	"additionalProperties": False,
	"properties": {
		field: schema
		for field, schema in _FIELDS.items()
		if field in frozenset([
			"email",
			"phone",
			"suspended",
			"data",
		])
	},
}

UPDATE_MY_CREDENTIALS = {
	"type": "object",
	"additionalProperties": False,
	"properties": {
		field: schema
		for field, schema in _FIELDS.items()
		if field in frozenset([
			"email",
			"phone",
		])
	},
}
