class TenantRequired(ValueError):
	pass


class NotAuthorized(Exception):
	"""
	Request for a resource that is not accessible within current session
	"""
	def __init__(self, message=None, *args, tenant=None, resource=None):
		self.Tenant = tenant
		self.Resource = resource

		if message is None:
			items = []
			if tenant is not None:
				items.append("tenant '{}'".format(tenant))
			if resource is not None:
				items.append("resource '{}'".format(resource))
			if len(items) > 0:
				message = "Not authorized for {}".format(", ".join(items))

		if message is None:
			super().__init__(*args)
		else:
			super().__init__(message, *args)
