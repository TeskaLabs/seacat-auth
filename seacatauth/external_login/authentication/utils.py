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
