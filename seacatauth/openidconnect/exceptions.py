class OpenIDConnectClientError(Exception):
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
