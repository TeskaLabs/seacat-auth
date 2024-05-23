import enum


class AuthOperation(enum.StrEnum):
	AddAccount = "a"
	LogIn = "l"
	SignUp = "s"

	@classmethod
	def deserialize(cls, value: str):
		if value == "a":
			return cls.AddAccount
		elif value == "l":
			return cls.LogIn
		elif value == "s":
			return cls.SignUp
		else:
			raise KeyError(value)
