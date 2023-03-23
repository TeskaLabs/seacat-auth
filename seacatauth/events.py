class EventTypes:
	LOGIN_SESSION_CREATED = "login_session_created"
	LOGIN_SESSION_UPDATED = "login_session_updated"

	WEBAUTHN_CREDENTIALS_CREATED = "webauthn_credentials_created"
	WEBAUTHN_CREDENTIALS_UPDATED = "webauthn_credentials_updated"
	WEBAUTHN_REG_CHALLENGE_CREATED = "webauthn_registration_challenge_created"

	RESOURCE_CREATED = "resource_created"
	RESOURCE_UPDATED = "resource_updated"
	RESOURCE_DELETED = "resource_deleted"
	RESOURCE_UNDELETED = "resource_undeleted"

	ROLE_CREATED = "role_created"
	ROLE_UPDATED = "role_updated"
	ROLE_ASSIGNED = "role_assigned"

	CLIENT_REGISTERED = "client_registered"
	CLIENT_UPDATED = "client_updated"
	CLIENT_SECRET_RESET = "client_secret_reset"

	PWD_RESET_TOKEN_CREATED = "pwd_reset_token_created"

	M2M_CREDENTIALS_CREATED = "m2m_credentials_created"
	CREDENTIALS_CREATED = "credentials_created"
	CREDENTIALS_UPDATED = "credentials_updated"

	EXTERNAL_LOGIN_CREATED = "external_login_created"

	OPENID_AUTH_CODE_GENERATED = "openid_auth_code_generated"

	TOTP_CREATED = "totp_secret_created"
	TOTP_REGISTERED = "totp_registered"

	SESSION_CREATED = "session_created"
	SESSION_UPDATED = "session_updated"
	SESSION_EXTENDED = "session_extended"

	TENANT_ASSIGNED = "tenant_assigned"
