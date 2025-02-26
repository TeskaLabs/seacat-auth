class ResourceId:
	SUPERUSER = "authz:superuser"
	IMPERSONATE = "authz:impersonate"
	ACCESS_ALL_TENANTS = "authz:tenant:access"

	CREDENTIALS_ACCESS = "seacat:credentials:access"
	CREDENTIALS_EDIT = "seacat:credentials:edit"

	TENANT_ACCESS = "seacat:tenant:access"
	TENANT_EDIT = "seacat:tenant:edit"
	TENANT_DELETE = "seacat:tenant:delete"
	TENANT_ASSIGN = "seacat:tenant:assign"

	ROLE_ACCESS = "seacat:role:access"
	ROLE_EDIT = "seacat:role:edit"
	ROLE_ASSIGN = "seacat:role:assign"

	RESOURCE_ACCESS = "seacat:resource:access"
	RESOURCE_EDIT = "seacat:resource:edit"

	CLIENT_ACCESS = "seacat:client:access"
	CLIENT_EDIT = "seacat:client:edit"

	SESSION_ACCESS = "seacat:session:access"
	SESSION_TERMINATE = "seacat:session:terminate"
