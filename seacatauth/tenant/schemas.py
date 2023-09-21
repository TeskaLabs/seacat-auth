_EDITABLE_TENANT_PROPERTIES = {
	"label": {
		"type": "string",
		"description": "Human-palatable tenant name.",
		"maxLength": 48},
	"description": {
		"type": "string",
		"description": "Extended tenant details."},
	"data": {
		"type": "object",
		"description":
			"Custom tenant data. Shallow JSON object that maps string keys "
			"to non-structured values.",
		"patternProperties": {
			"^[a-zA-Z][a-zA-Z0-9_-]{0,126}[a-zA-Z0-9]$": {"anyOf": [
				{"type": "string"},
				{"type": "number"},
				{"type": "boolean"},
				{"type": "null"}]}}}}

CREATE_TENANT = {
	"type": "object",
	"required": ["id"],
	"additionalProperties": False,
	"properties": {
		"id": {
			"type": "string",
			"description": "Unique tenant ID. Can't be changed once the tenant has been created."},
		**_EDITABLE_TENANT_PROPERTIES},
	"example": {
		"id": "acme-corp"}
}

UPDATE_TENANT = {
	"type": "object",
	"additionalProperties": False,
	"properties": _EDITABLE_TENANT_PROPERTIES,
	"example": {
		"label": "ACME Corp Inc.",
		"data": {
			"email": "support@acmecorp.test",
			"very_corporate": True,
			"schema": "ECS"}}
}

SET_TENANTS = {
	"type": "object",
	"required": ["tenants"],
	"properties": {
		"tenants": {
			"type": "array",
			"description": "List of the IDs of tenants to be set",
			"items": {"type": "string"}}},
	"example": {
		"tenants": ["acme-corp", "my-eshop"]}
}

GET_TENANTS_BATCH = {
	"type": "array",
	"description": "List of credential IDs",
	"items": {"type": "string"},
	"example": ["mongodb:default:abc123def456", "htpasswd:local:zdenek"],
}

BULK_ASSIGN_TENANTS = {
	"type": "object",
	"required": ["credential_ids", "tenants"],
	"properties": {
		"credential_ids": {
			"type": "array",
			"description": "List of the IDs of credentials to manage.",
			"items": {"type": "string"}},
		"tenants": {
			"type": "object",
			"description":
				"Tenants and roles to be assigned. \n\n"
				"The keys are the IDs of tenants to be granted access to. The values are arrays of the respective "
				"tenant's roles to be assigned. \n\n"
				"To grant tenant access without assigning any roles, "
				"leave the role array empty. \n\n"
				"To assign global roles, list them under the `'*'` key.",
			"patternProperties": {
				r"^\*$|^[a-z][a-z0-9._-]{2,31}$": {
					"type": "array",
					"description": "List of the tenant's roles to be assigned",
					"items": {"type": "string"}}}}},
	"example": {
		"credential_ids": [
			"mongodb:default:abc123def456", "htpasswd:local:zdenek"],
		"tenants": {
			"*": ["*/global-editor"],
			"acme-corp": ["acme-corp/user", "acme-corp/supervisor"],
			"my-eshop": []}},
}

BULK_UNASSIGN_TENANTS = {
	"type": "object",
	"required": ["credential_ids", "tenants"],
	"properties": {
		"credential_ids": {
			"type": "array",
			"description": "List of the IDs of credentials to manage.",
			"items": {"type": "string"}},
		"tenants": {
			"type": "object",
			"description":
				"Tenants and roles to be unassigned. \n\n"
				"The keys are the IDs of tenants to be revoked access to. The values are arrays of the respective "
				"tenant's roles to be unassigned. \n\n"
				"To completely revoke credentials' access to the tenant, provide `\"UNASSIGN-TENANT\"` as the "
				"tenant value, instead of the array of roles. \n\n"
				"To unassign global roles, list them under the `\"*\"` key.",
			"patternProperties": {
				r"^\*$|^[a-z][a-z0-9._-]{2,31}$": {
					"anyOf": [
						{"type": "array", "items": {"type": "string"}},
						{"type": "string", "enum": ["UNASSIGN-TENANT"]}
					]}}}},
	"example": {
		"credential_ids": [
			"mongodb:default:abc123def456", "htpasswd:local:zdenek"],
		"tenants": {
			"*": ["*/global-editor"],
			"acme-corp": ["acme-corp/user", "acme-corp/supervisor"],
			"my-eshop": "UNASSIGN-TENANT"}},
}
