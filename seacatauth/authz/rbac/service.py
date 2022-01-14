import logging

import asab

#
import typing

L = logging.getLogger(__name__)

#


class RBACService(asab.Service):

	def __init__(self, app, service_name="seacatauth.RBACService"):
		super().__init__(app, service_name)

	@staticmethod
	def has_resource_access(authz: dict, tenant: typing.Union[str, None], requested_resources: list):
		# Superuser passes without further checks
		global_resources = set(
			resource
			for resources in authz["*"].values()
			for resource in resources
		)
		if "authz:superuser" in global_resources:
			return "OK"

		if tenant == "*":
			# If the tenant is "*", we are performing a soft-check, i.e. checking if the resource is under ANY tenant
			# Gather resources from all tenants
			resources = set(
				resource
				for roles in authz.values()
				for resources in roles.values()
				for resource in resources
			)
		elif tenant is None:
			# If the tenant is None, we check only global roles
			resources = set(
				resource
				for resources in authz["*"].values()
				for resource in resources
			)
		elif tenant in authz:
			# We are checking resources under a specific tenant
			resources = set(
				resource
				for resources in authz[tenant].values()
				for resource in resources
			)
		else:
			# Inaccessible tenant
			return "NOT-AUTHORIZED"

		# Validate the resources
		for resource in requested_resources:

			if resource == "tenant:access":
				if tenant is None:
					# "tenant:access" must be paired with a specific tenant
					return "TENANT-NOT-SPECIFIED"
				if tenant == "*":
					# Soft-check: Pass if at least one tenant is accessible
					# (Authz must contain "*" plus at least one more tenant)
					if len(authz) >= 2:
						continue
					return "NOT-AUTHORIZED"
				if tenant not in authz:
					return "NOT-AUTHORIZED"
				continue

			if resource in resources:
				continue
			return "NOT-AUTHORIZED"

		return "OK"
