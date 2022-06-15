import logging
import functools
import inspect

import aiohttp.web

#

L = logging.getLogger(__name__)

#


def access_control(resource=None):
	"""
	This handler decorator fulfills the following purposes:
	- auhtenticate the request,
	- perform tenant access authorization, if the request is tenant-specific,
	- perform resource access authorization, if the `resource` argument is not None,
	- pass `credentials_id`, `tenant` and/or `resources` to the decorated function.

	#############
	##  USAGE

	1) Only authenticate the request.
		```
		web_app.router.add_get('/user_details', self.user_details)

		@access_control()
		async def user_details(self, request, *, credentials_id):
			...
		```

	2) Authenticate the request and authorize access to the `resource` in the decorator argument.
	There is no `tenant` in the URL and the request is considered tenantless.
	Only global resources are checked in the authorization process.
		```
		web_app.router.add_get('/user_details', self.user_details)

		@access_control("details:read")
		async def user_details(self, request, *, credentials_id):
			...
		```

	3) Authenticate the request and authorize tenant access.
	Path variable `tenant` must be present in the URL so that there is a tenant to authorize with.
		```
		web_app.router.add_get('/{tenant}/list', self.list)

		@access_control()
		async def list(self, request, *, tenant):
			...
		```

	4) Authenticate the request, authorize access to tenant and to the `resource` in the decorator argument.
	Path variable `tenant` must be present in the URL so that there is a tenant to authorize with.
		```
		web_app.router.add_get('/{tenant}/list', self.list)

		@access_control("list:read")
		async def list(self, request, *, tenant):
			...
		```
	"""

	def decorator(handler):

		# Inspect the signature of the decorated function for relevant kwargs
		handler_argspecs = inspect.getfullargspec(handler)
		handler_kwargs = {}

		# Add keyword arguments
		if "credentials_id" in handler_argspecs.kwonlyargs:
			handler_kwargs["credentials_id"] = None
		if "tenant" in handler_argspecs.kwonlyargs:
			handler_kwargs["tenant"] = None
		if "resources" in handler_argspecs.kwonlyargs:
			handler_kwargs["resources"] = None

		@functools.wraps(handler)
		async def wrapper(*args, **kwargs):

			# 1) Authenticate
			# Retrieve the session object
			request = args[-1]

			# Session must be provided by auth_middleware at this point
			# If not, something has gone wrong
			if request.Session is None:
				L.error("Unauthenticated access: session missing")
				raise aiohttp.web.HTTPUnauthorized()

			# 2) Authorize tenant
			# Use the session object to extend the request with credentials_id, requested tenant and set of resources.
			# If no tenant is present in the request, the request is considered global (i.e. `request.Tenant = "*"`)
			# and tenant access authorization always passes.
			request = _authorize_tenant(request)

			# 3) Authorize resource
			# (if the decorator specifies a required `resource`)
			if resource is not None:
				if resource not in request.Resources \
					and "authz:superuser" not in request.Resources:
					L.warning("Unauthorized access", struct_data={
						"cid": request.CredentialsId,
						"requested_tenant": request.Tenant,
						"required_resource": resource
					})
					raise aiohttp.web.HTTPForbidden()

			# Add keyword arguments
			if "credentials_id" in handler_kwargs:
				handler_kwargs["credentials_id"] = request.CredentialsId
			if "tenant" in handler_kwargs:
				handler_kwargs["tenant"] = request.Tenant
			if "resources" in handler_kwargs:
				handler_kwargs["resources"] = request.Resources

			return await handler(*args, **kwargs, **handler_kwargs)

		return wrapper

	return decorator


def _authorize_tenant(request):
	"""
	Extract and authorize the requested tenant
	If there's no tenant in the request or if the tenant is "*", no tenant-authorization happens
	"""
	requested_tenant = request.match_info.get("tenant")

	# Gather resources from all global roles
	available_resources = set().union(request.Session.Authorization.Authz.get("*"))

	# Check for tenant access
	if requested_tenant in (None, "*"):
		# Global space is accessible to anyone
		pass
	elif requested_tenant in request.Session.Authorization.Authz:
		# Tenant accessible
		# Add resources from all roles under the requested_tenant
		available_resources = available_resources.union(request.Session.Authorization.Authz.get(requested_tenant))
	elif "authz:superuser" in available_resources:
		# Bypassing tenant-access check as superuser
		# No resources to add
		pass
	else:
		# Tenant access denied
		L.warning("Unauthorized access", struct_data={
			"cid": request.Session.Credentials.Id,
			"requested_tenant": requested_tenant
		})
		raise aiohttp.web.HTTPForbidden()

	# Add credentials and tenant info to request
	request.CredentialsId = request.Session.Credentials.Id
	request.Tenant = requested_tenant
	request.Resources = available_resources

	return request
