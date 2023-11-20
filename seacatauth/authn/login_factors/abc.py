import abc


class LoginFactorABC(abc.ABC):
	Type = None
	# Authentication Method Reference
	# https://www.rfc-editor.org/rfc/rfc8176.html
	AMRValue = None

	def __init__(self, authn_service, config):
		self.AuthenticationService = authn_service

	def __repr__(self):
		return "{}[{}]".format(
			self.__class__.__name__,
			str({
				"type": self.Type
			})
		)

	def serialize(self):
		"""
		Used in HTTP JSON responses.
		"""
		return {"type": self.Type}

	async def is_eligible(self, login_data: dict) -> bool:
		# TODO: Refactor login_data into explicit kwargs
		"""
		Returns True if the factor can be used for authentication.
		E.g.:
			"password" factor is eligible only for credentials with a configured password,
			"smscode" factor is eligible only for credentials with a phone number,
			"subnet" factor is eligible only if the login request originates from a specified IP address range

		:param login_data: Contains "credentials_id" and other login information that may be needed by login factors.
		"""
		raise NotImplementedError()

	async def authenticate(self, login_session, request_data) -> bool:
		"""
		Returns True if this factor's authentication criteria are fulfilled.
		"""
		raise NotImplementedError()
