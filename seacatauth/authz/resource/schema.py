CREATE_OR_UNDELETE_RESOURCE = {
	"type": "object",
	"additionalProperties": False,
	"properties": {
		"description": {"type": "string"},
		"global_only": {
			"type": "boolean",
			"description":
				"If set to true, the resource has a global scope and cannot be granted via tenant-specific roles. "
				"This attribute cannot be changed later.",
			"default": False,
		},
	}
}

UPDATE_RESOURCE = {
	"type": "object",
	"additionalProperties": False,
	"properties": {
		"name": {"type": "string"},
		"description": {"type": "string"},
	}
}
