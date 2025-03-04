import typing
import asab
import asab.web.auth.authorization

from ...models.const import ResourceId


# TODO: Deprecated. Replace with ASAB auth functions entirely.
class RBACService(asab.Service):

	def __init__(self, app, service_name="seacatauth.RBACService"):
		super().__init__(app, service_name)

	@staticmethod
	def is_superuser(authz: dict) -> bool:
		return asab.web.auth.authorization.is_superuser(authz)

	@staticmethod
	def can_access_all_tenants(authz: dict) -> bool:
		return asab.web.auth.authorization.has_resource_access(authz, [ResourceId.ACCESS_ALL_TENANTS], tenant=None)

	@staticmethod
	def has_resource_access(authz: dict, tenant: typing.Union[str, None], requested_resources: list) -> bool:
		return asab.web.auth.authorization.has_resource_access(authz, requested_resources, tenant)

	@staticmethod
	def has_tenant_access(authz: dict, tenant: typing.Union[str, None]) -> bool:
		return asab.web.auth.authorization.has_tenant_access(authz, tenant)
