CREATE_OR_UNDELETE_RESOURCE = {
	"type": "object",
	"additionalProperties": False,
	"properties": {
		"description": {"type": "string"}}
}

UPDATE_RESOURCE = {
	"type": "object",
	"additionalProperties": False,
	"properties": {
		"name": {"type": "string"},
		"description": {"type": "string"},
	}
}
