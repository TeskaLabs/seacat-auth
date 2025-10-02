from ..exceptions import SeacatAuthError


class ExternalAccountNotFoundError(SeacatAuthError, KeyError):
	"""
	External login account not found
	"""
	def __init__(self, provider_type: str, subject_id: str, *args):
		self.ProviderType = provider_type
		self.SubjectId = subject_id
		super().__init__("External login account {!r} not found in provider {!r}".format(
			self.SubjectId, self.ProviderType), *args)


class ExternalLoginError(SeacatAuthError):
	"""
	Failed to complete external login flow
	"""
	def __init__(self, message: str, *args):
		super().__init__(message, *args)
