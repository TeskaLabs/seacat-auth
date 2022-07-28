class OAuth2ClientError(Exception):
	pass


class InvalidClientID(OAuth2ClientError):
	def __init__(self, client_id, *args):
		self.ClientID = client_id
		message = "Invalid OAuth2 client {!r}".format(client_id)
		super().__init__(message, *args)


class InvalidClientSecret(OAuth2ClientError):
	def __init__(self, client_id, *args):
		self.ClientID = client_id
		message = "Invalid client secret for OAuth2 client {!r}".format(client_id)
		super().__init__(message, *args)


class ForbiddenScope(OAuth2ClientError):
	def __init__(self, client_id, scope, *args):
		self.ClientID = client_id
		self.Scope = scope
		message = "Scope {!r} not allowed for OAuth2 client {!r}".format(client_id, scope)
		super().__init__(message, *args)


class ForbiddenRedirectURI(OAuth2ClientError):
	def __init__(self, client_id, redirect_uri, *args):
		self.ClientID = client_id
		self.RedirectURI = redirect_uri
		message = "Redirect URI {!r} not allowed for OAuth2 client {!r}".format(redirect_uri, client_id)
		super().__init__(message, *args)
