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
	def __init__(self, subject, *args):
		super().__init__(
			"Subject {!r} does not have access to any tenant".format(subject), subject=subject, *args)


class TenantNotFoundError(SeacatAuthError, KeyError):
	"""
	Tenant not found
	"""
	def __init__(self, tenant, *args):
		self.Tenant = tenant
		super().__init__("Tenant {!r} not found".format(self.Tenant), *args)


class RoleNotFoundError(SeacatAuthError, KeyError):
	"""
	Role not found
	"""
	def __init__(self, role, *args):
		self.Role = role
		super().__init__("Role {!r} not found".format(self.Role), *args)


class CredentialsNotFoundError(SeacatAuthError, KeyError):
	"""
	Credentials not found
	"""
	def __init__(self, credentials_id, *args):
		self.CredentialsId = credentials_id
		super().__init__("Credentials {!r} not found".format(self.CredentialsId), *args)


class LoginPrologueDeniedError(SeacatAuthError):
	"""
	Seacat login prologue was denied
	"""
	def __init__(self, message, *args):
		super().__init__(message, *args)


class CredentialsSuspendedError(SeacatAuthError):
	"""
	Credentials not active
	"""
	def __init__(self, credentials_id, *args):
		self.CredentialsId = credentials_id
		super().__init__("Credentials {!r} suspended".format(self.CredentialsId), *args)


class UnauthorizedTenantAccessError(AccessDeniedError):
	"""
	Session not authorized for the tenant.
	"""
	def __init__(self, session, tenant, credentials_id=None, *args):
		self.Session = session
		self.CredentialsId = credentials_id
		self.Tenant = tenant
		super().__init__(
			"{!r} is not authorized to access tenant {!r}".format(self.Session, self.Tenant),
			subject=self.CredentialsId,
			*args
		)


class TenantNotAssignedError(SeacatAuthError, KeyError):
	"""
	Credentials do not have the tenant assigned.
	"""
	def __init__(self, credentials_id, tenant, *args):
		self.CredentialsId = credentials_id
		self.Tenant = tenant
		super().__init__("Credentials do not have the tenant assigned.", *args)


class TOTPActivationError(SeacatAuthError):
	"""
	Failed to activate TOTP
	"""
	def __init__(self, message: str, credentials_id: str):
		self.CredentialsID: str = credentials_id
		super().__init__(message)


class TOTPDeactivationError(SeacatAuthError):
	"""
	Failed to deactivate TOTP
	"""
	def __init__(self, message: str, credentials_id: str):
		self.CredentialsID: str = credentials_id
		super().__init__(message)


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


class MessageDeliveryError(SeacatAuthError):
	"""
	Failed to send message
	"""
	def __init__(self, message, channel, template_id=None, *args):
		self.TemplateId = template_id
		self.Channel = channel
		super().__init__(message, *args)


class CommunicationNotConfiguredError(SeacatAuthError):
	"""
	No communication channels are configured
	"""
	def __init__(self,  *args):
		super().__init__("No communication channels are configured.", *args)


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
