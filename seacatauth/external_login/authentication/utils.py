import enum


class AuthOperation(enum.StrEnum):
	PairAccount = "p"
	LogIn = "l"
	SignUp = "s"

	@classmethod
	def deserialize(cls, value: str):
		if value == cls.PairAccount:
			return cls.PairAccount
		elif value == cls.LogIn:
			return cls.LogIn
		elif value == cls.SignUp:
			return cls.SignUp
		else:
			raise KeyError(value)


class ExtLoginResult(enum.StrEnum):
	SIGNUP_SUCCESS = "signup_success"
	PAIRING_SUCCESS = "pairing_success"
	LOGIN_SUCCESS = "login_success"
	LOGIN_FAILED = "login_failed"
	SIGNUP_FAILED = "signup_failed"
	PAIRING_FAILED = "pairing_failed"


class ExtLoginError(enum.StrEnum):
	REGISTRATION_DISABLED = "registration_disabled"
	NOT_AUTHENTICATED = "not_authenticated"
	ALREADY_EXISTS = "already_exists"
	NOT_FOUND = "not_found"
	ACCESS_DENIED = "access_denied"
