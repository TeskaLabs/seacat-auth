import enum


class AuditCode(enum.Enum):

	def _generate_next_value_(name, start, count, last_values):
		return name

	LOGIN_SUCCESS = enum.auto()
	LOGIN_FAILED = enum.auto()
	PASSWORD_CHANGE_SUCCESS = enum.auto()
	PASSWORD_CHANGE_FAILED = enum.auto()
