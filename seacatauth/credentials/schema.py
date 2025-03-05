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
		"description": "Email address",
		"anyOf": [
			{"type": "string", "enum": [""]},
			{"type": "string", "format": "email"},
		],
	},
	"phone": {
		"description": "Mobile number",
		"anyOf": [
			{"type": "string", "enum": [""]},
			{"type": "string", "pattern": r"^\+?[0-9 ]+$"},
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

GET_IDENTS_FROM_IDS = {
	"type": "array",
	"items": {
		"type": "string"
	}
}

ENFORCE_FACTORS = {
	"type": "object",
	"additionalProperties": False,
	"required": ["factors"],
	"properties": {
		"factors": {
			"type": "array",
			"description": "Factors to enforce/reset",
			"items": {"type": "string"}
		}
	}
}

CREATE_INVITATION_PUBLIC = {
	"type": "object",
	"required": ["email"],  # TODO: Enable more communication options
	"additionalProperties": False,
	"properties": {
		"email": {"type": "string"},
		"invitation_link": {
			"enum": ["email", "response"],
		},
	}
}

CREATE_INVITATION_ADMIN = {
	"type": "object",
	"required": ["credentials"],
	"additionalProperties": False,
	"properties": {
		"credentials": {
			"required": ["email"],  # TODO: Enable more communication options
			"properties": {
				"email": {"type": "string"},
				"username": {"type": "string"},
				"phone": {"type": "string"},
			}
		},
		"invitation_link": {
			"enum": ["email", "response"],
		},
		"expiration": {
			"oneOf": [{"type": "string"}, {"type": "number"}],
			"description": "How long until the invitation expires.",
			"example": "6 h",
		},
	},
}

REQUEST_SELF_INVITATION = {
	"type": "object",
	"required": ["email"],
	"additionalProperties": False,
	"properties": {
		"email": {
			"type": "string",
			"description": "User email to send the invitation to."},
	},
}

CHANGE_PASSWORD = {
	"type": "object",
	"required": [
		"oldpassword",
		"newpassword",
	],
	"properties": {
		"oldpassword": {"type": "string"},
		"newpassword": {"type": "string"},
	}
}

RESET_PASSWORD = {
	"type": "object",
	"required": [
		"newpassword",
		"pwd_token",  # Password reset token
	],
	"properties": {
		"newpassword": {
			"type": "string",
		},
		"pwd_token": {
			"type": "string",
			"description": "One-time code for password reset",
		},
	}
}

REQUEST_PASSWORD_RESET_ADMIN = {
	"type": "object",
	"required": ["credentials_id"],
	"properties": {
		"credentials_id": {"type": "string"},
		"expiration": {"type": "number"},
	}
}

REQUEST_LOST_PASSWORD_RESET = {
	"type": "object",
	"required": ["ident"],
	"properties": {
		"ident": {"type": "string"},
	}
}
