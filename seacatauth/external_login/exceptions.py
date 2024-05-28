from ..exceptions import SeacatAuthError

class ExternalLoginError(SeacatAuthError):
	def __init__(
		self,
		message: str,
		*args,
		credentials_id: str = None,
		provider_type: str = None,
		subject_id: str = None,
		**kwargs
	):
		self.CredentialsId: str = credentials_id
		self.ProviderType: str = provider_type
		self.SubjectID: str = subject_id
		super().__init__(message, *args)


class ExternalAccountNotFoundError(SeacatAuthError, KeyError):
	"""
	External login account not found
	"""
	def __init__(self, provider_type: str, sub: str, *args):
		self.ProviderType = provider_type
		self.SubjectId = sub
		super().__init__("External login account {!r} not found in provider {!r}".format(
			self.SubjectId, self.ProviderType), *args)


class ExternalAccountAlreadyUsedError(ExternalLoginError):
	def __init__(
		self,
		provider_type: str,
		subject_id: str,
		*args,
		credentials_id: str = None,
		**kwargs
	):
		super().__init__(
			"External account already used",
			*args,
			credentials_id=credentials_id,
			provider_type=provider_type,
			subject_id=subject_id,
		)
