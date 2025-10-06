from ..exceptions import SeacatAuthError


class ExternalAccountNotFoundError(SeacatAuthError, KeyError):
	"""
	External login account not found
	"""
	def __init__(self, *args, query, **kwargs):
		self.Query = query
		super().__init__("No external credentials matched the query {!r}".format(self.Query), *args)


class ExternalLoginError(SeacatAuthError):
	"""
	Failed to complete external login flow
	"""
	def __init__(self, message: str, *args):
		super().__init__(message, *args)
