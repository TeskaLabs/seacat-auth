import typing


class SeacatAuthError(Exception):
	"""
	Generic Seacat Auth error
	"""
	pass


class TenantNotSpecifiedError(SeacatAuthError):
	"""
	No tenant specified in a tenant-dependent context
	"""
	pass


class AccessDeniedError(SeacatAuthError):
	"""
	Subject is not authorized to access requested resource (or tenant, operation...).

	Equivalent to HTTP 403 Forbidden.
	"""
	def __init__(self, message=None, *args, subject=None, resource=None):
		self.Subject = subject
		self.Resource = resource
		if message is not None:
			super().__init__(message, *args)
		elif resource is not None:
			if subject is not None:
				message = "Subject {!r} is not authorized to access {!r}.".format(subject, resource)
			else:
				message = "Not authorized to access {!r}.".format(resource)
			super().__init__(message, *args)
		else:
			super().__init__(*args)


class TenantAccessDeniedError(AccessDeniedError):
	"""
	Subject is not authorized to access requested tenant.
	"""
	def __init__(self, tenant, subject=None):
		self.Tenant = tenant
		super().__init__(subject=subject, resource=tenant)


class NoTenantsError(AccessDeniedError):
	"""
	Subject has access to no tenants.
	"""
	def __init__(self, subject=None, *args):
		self.Subject = subject
		super().__init__("Subject has access to no tenant.", *args)


class TenantNotFoundError(SeacatAuthError, KeyError):
	"""
	Tenant not found
	"""
	def __init__(self, tenant, *args):
		self.Tenant = tenant
		super().__init__("Tenant not found.", *args)


class RoleNotFoundError(SeacatAuthError, KeyError):
	"""
	Role not found
	"""
	def __init__(self, role, *args):
		self.Role = role
		super().__init__("Role not found.", *args)


class CredentialsNotFoundError(SeacatAuthError, KeyError):
	"""
	Credentials not found
	"""
	def __init__(self, credentials_id, *args):
		self.CredentialsId = credentials_id
		super().__init__("Credentials not found.", *args)


class UnauthorizedTenantAccessError(AccessDeniedError):
	"""
	Session not authorized for the tenant.
	"""
	def __init__(self, session_id, tenant, credentials_id=None, *args):
		self.SessionId = session_id
		self.CredentialsId = credentials_id
		self.Tenant = tenant
		super().__init__("Credentials are not authorized under tenant.", *args)


class TenantNotAssignedError(SeacatAuthError, KeyError):
	"""
	Credentials do not have the tenant assigned.
	"""
	def __init__(self, credentials_id, tenant, *args):
		self.CredentialsId = credentials_id
		self.Tenant = tenant
		super().__init__("Credentials do not have the tenant assigned.", *args)


class TOTPNotActiveError(SeacatAuthError):
	"""
	Credentials do not have any registered TOTP secret
	"""
	def __init__(self, credential_id: str):
		self.CredentialID: str = credential_id
		super().__init__("TOTP not active for credentials.")


class ClientResponseError(SeacatAuthError):
	"""
	OAuth client responded with HTTP error
	"""
	def __init__(self, status: int, data: typing.Union[str, dict]):
		self.Status = status
		self.Data = data
		super().__init__("Client responded with error {}: {}".format(status, data))


class SessionNotFoundError(SeacatAuthError, KeyError):
	"""
	Missing or expired session
	"""
	def __init__(self, message, session_id=None, query=None, *args):
		self.SessionId = session_id
		self.Query = query
		super().__init__(message, *args)


class CommunicationError(SeacatAuthError):
	"""
	Failed to send notification or message
	"""
	def __init__(self, message, credentials_id=None, *args):
		self.CredentialsId = credentials_id
		super().__init__(message, *args)


class NoCookieError(SeacatAuthError):
	"""
	Request has no (roo or client) cookie
	"""
	def __init__(self, client_id=None, *args):
		self.ClientId = client_id
		if self.ClientId:
			message = "Request contains no cookie of client {!r}".format(self.ClientId)
		else:
			message = "Request contains no root session cookie"
		super().__init__(message, *args)


class IntegrityError(SeacatAuthError):
	"""
	Database is in an unexpected state; on object is missing its dependencies.
	"""
	def __init__(self, message, **struct_data):
		self.StructData = struct_data
		super().__init__(message)
