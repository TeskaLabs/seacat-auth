import enum


class AuditCode(enum.Enum):

	def _generate_next_value_(name, start, count, last_values):
		return name

	LOGIN_SUCCESS = enum.auto()
	LOGIN_FAILED = enum.auto()
	M2M_AUTHENTICATION_SUCCESSFUL = enum.auto()
	ANONYMOUS_SESSION_CREATED = enum.auto()
	PASSWORD_CHANGE_SUCCESS = enum.auto()
	PASSWORD_CHANGE_FAILED = enum.auto()
	AUTHORIZE_SUCCESS = enum.auto()
	AUTHORIZE_ERROR = enum.auto()
	CREDENTIALS_CREATED = enum.auto()
	CREDENTIALS_UPDATED = enum.auto()
	CREDENTIALS_DELETED = enum.auto()
	CREDENTIALS_INVITATION_CREATED = enum.auto()
	CREDENTIALS_REGISTERED_NEW = enum.auto()
	CREDENTIALS_REGISTERED_EXISTING = enum.auto()
	IMPERSONATION_SUCCESSFUL = enum.auto()
	IMPERSONATION_FAILED = enum.auto()
