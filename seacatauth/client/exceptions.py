class ClientError(Exception):
	def __init__(self, *args, client_id, **kwargs):
		self.ClientID = client_id
		self.Key = None
		self.Value = None
		if len(kwargs) > 0:
			self.Key, self.Value = kwargs.popitem()
			message = "Invalid {key} '{value}' for client '{client_id}'".format(
				client_id=client_id, key=self.Key, value=self.Value)
			super().__init__(message, *args)
		else:
			super().__init__(*args)


class InvalidRedirectURI(ClientError):
	def __init__(self, *args, client_id, redirect_uri):
		self.RedirectURI = redirect_uri
		super().__init__(*args, client_id=client_id, redirect_uri=redirect_uri)


class InvalidClientSecret(ClientError):
	def __init__(self, client_id, *args):
		message = "Invalid client secret for client '{client_id}'".format(client_id=client_id)
		super().__init__(message, *args, client_id=client_id)


class ClientNotFoundError(ClientError):
	def __init__(self, client_id, *args):
		message = "Client '{client_id}' not found".format(client_id=client_id)
		super().__init__(message, *args, client_id=client_id)
