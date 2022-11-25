class TenantRequired(Exception):
	pass


class AuthenticationRequired(Exception):
	"""
	Accessing this resource (or tenant, operation...) requires that the subject be authenticated.

	Equivalent to HTTP 401 Unauthorized.
	"""
	pass


class NotAuthorized(Exception):
	"""
	Subject is not authorized to access requested resource (or tenant, operation...).

	Equivalent to HTTP 403 Forbidden.
	"""
	def __init__(self, message=None, *args, subject=None, resource=None):
		self.Subject = subject
		self.Resource = subject
		if message is not None:
			super().__init__(message, *args)
		elif resource is not None:
			if subject is not None:
				message = "Subject '{}' is not authorized to access '{}'.".format(subject, resource)
			else:
				message = "Not authorized to access '{}'.".format(resource)
			super().__init__(message, *args)
		else:
			super().__init__(*args)
