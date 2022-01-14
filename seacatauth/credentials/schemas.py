# TODO: Handle schema building systematically in a dedicated class
#   Connect with Policy class

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
	"required": [
		"username"
	],
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
