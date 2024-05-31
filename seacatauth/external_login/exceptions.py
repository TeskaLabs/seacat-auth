import typing

from ..exceptions import SeacatAuthError

class ExternalAccountError(SeacatAuthError):
	Result = None

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

	def get_log_struct_data(self):
		struct_data = {}
		if self.CredentialsId:
			struct_data["cid"] = self.CredentialsId
		if self.ProviderType:
			struct_data["provider"] = self.ProviderType
		if self.SubjectId:
			struct_data["sub"] = self.SubjectId
		return struct_data or None


class LoginWithExternalAccountError(ExternalAccountError):
	Result = "login_failed"


class SignupWithExternalAccountError(ExternalAccountError):
	Result = "signup_failed"


class PairingExternalAccountError(ExternalAccountError):
	Result = "pairing_failed"


class ExternalAccountNotFoundError(SeacatAuthError, KeyError):
	"""
	External login account not found
	"""
	def __init__(self, provider_type: str, subject_id: str, *args):
		self.ProviderType = provider_type
		self.SubjectId = subject_id
		super().__init__("External login account {!r} not found in provider {!r}".format(
			self.SubjectId, self.ProviderType), *args)
