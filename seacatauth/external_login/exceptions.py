import typing

from ..exceptions import SeacatAuthError


class ExternalAccountError(SeacatAuthError):
	Result: typing.Optional[str] = None

	def __init__(
		self,
		message: str,
		*args,
		credentials_id: typing.Optional[str] = None,
		provider_type: typing.Optional[str] = None,
		subject_id: typing.Optional[str] = None,
		redirect_uri: typing.Optional[str] = None,
		**kwargs
	):
		super().__init__(message, *args)
		self.CredentialsId = credentials_id
		self.ProviderType = provider_type
		self.SubjectId = subject_id
		self.RedirectUri = redirect_uri


class LoginWithExternalAccountError(ExternalAccountError):
	Result = "login_error"


class SignupWithExternalAccountError(ExternalAccountError):
	Result = "signup_error"


class PairingExternalAccountError(ExternalAccountError):
	Result = "pairing_error"


class ExternalAccountNotFoundError(SeacatAuthError, KeyError):
	"""
	External login account not found
	"""
	def __init__(self, provider_type: str, subject_id: str, *args):
		self.ProviderType = provider_type
		self.SubjectId = subject_id
		super().__init__("External login account {!r} not found in provider {!r}".format(
			self.SubjectId, self.ProviderType), *args)


class ExternalOAuthFlowError(SeacatAuthError):
	"""
	Failed to complete OAuth 2.0 Authorization Code flow at external identity provider
	"""
	def __init__(self, message: str, *args):
		super().__init__(message, *args)
