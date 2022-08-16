import logging
import typing

import asab

from ...exceptions import TenantRequired

#

L = logging.getLogger(__name__)

#


class RBACService(asab.Service):

	def __init__(self, app, service_name="seacatauth.RBACService"):
		super().__init__(app, service_name)

	@staticmethod
	def is_superuser(authz: dict):
		global_resources = set(
			resource
			for resource in authz["*"]
		)
		return "authz:superuser" in global_resources

	@staticmethod
	def has_resource_access(authz: dict, tenant: typing.Union[str, None], requested_resources: list):
		# Superuser passes without further checks
		if RBACService.is_superuser(authz):
			return True

		if tenant == "*":
			# If the tenant is "*", we are performing a soft-check, i.e. checking if the resource is under ANY tenant
			# Gather resources from all tenants
			resources = set(
				resource
				for resources in authz.values()
				for resource in resources
			)
		elif tenant is None:
			# If the tenant is None, we check only global roles
			resources = set(
				resource
				for resource in authz["*"]
			)
		elif tenant in authz:
			# We are checking resources under a specific tenant
			resources = set(
				resource
				for resource in authz[tenant]
			)
		else:
			# Inaccessible tenant
			return False

		# Validate the resources
		for resource in requested_resources:

			if resource == "tenant:access":
				if tenant is None:
					# "tenant:access" must be checked against a specific tenant
					raise TenantRequired()
				if "authz:tenant:access" in authz["*"]:
					# "authz:tenant:access" grants access to all tenants
					continue
				if tenant == "*":
					# Soft-check: Pass if at least one tenant is accessible
					# (Authz must contain "*" plus at least one more tenant)
					if len(authz) >= 2:
						continue
					return False
				if tenant not in authz:
					return False
				continue

			if resource in resources:
				continue
			return False

		return True
