class EventTypes:
	EVENT_TYPE = "event_type"
	LOGIN_SESSION_CREATED = "login_session_created"
	LOGIN_SESSION_UPDATED = "login_session_updated"

	WEBAUTHN_CREDENTIAL_CREATED = "webauthn_credential_created"
	WEBAUTHN_CREDENTIAL_UPDATED = "webauthn_credential_updated"
	REGISTRATION_CHALLENGE_CREATED = "registration_challenge_created"

	RESOURCE_CREATED = "resource_created"
	RESOURCE_UPDATED = "resource_updated"
	RESOURCE_DELETED = "resource_deleted"
	RESOURCE_UNDELETED = "resource_undeleted"

	ROLE_CREATED = "role_created"
	ROLE_UPDATED = "role_updated"
	ROLE_ASSIGNED = "role_assigned"
	ROLES_ASSIGNED = "roles_assigned"

	CLIENT_REGISTERED = "client_registered"
	CLIENT_UPDATED = "client_updated"
	CLIENT_RESET = "client_reset"

	PWD_RESET_TOKEN_CREATED = "pwd_reset_token_created"

	M2M_MONGO_CREDENTIALS_CREATED = "m2m_mongo_credentials_created"
	MONGO_CREDENTIALS_CREATED = "mongo_credentials_created"
	MONGO_CREDENTIALS_UPDATED = "mongo_credentials_updated"
