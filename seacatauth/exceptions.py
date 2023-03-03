class TenantNotSpecifiedError(Exception):
	pass


class AccessDeniedError(Exception):
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


class TenantNotFoundError(KeyError):
	def __init__(self, tenant, *args):
		self.Tenant = tenant
		super().__init__("Tenant not found.", *args)


class RoleNotFoundError(KeyError):
	def __init__(self, role, *args):
		self.Role = role
		super().__init__("Role not found.", *args)


class CredentialsNotFoundError(KeyError):
	def __init__(self, credentials_id, *args):
		self.CredentialsId = credentials_id
		super().__init__("Credentials not found.", *args)


class TenantNotAuthorizedError(AccessDeniedError):
	"""
	Credentials do not have access to tenant
	"""
	def __init__(self, credentials_id, tenant, *args):
		self.CredentialsId = credentials_id
		self.Tenant = tenant
		super().__init__("Credentials not authorized under tenant.", *args)
