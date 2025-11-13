import typing
import logging
import asab

from .role.view.propagated_role import global_role_id_to_propagated
from .. import exceptions
from ..api import local_authz
from ..models.const import ResourceId


L = logging.getLogger(__name__)


async def build_credentials_authz(
	tenant_service, role_service, credentials_id: str,
	tenants: typing.Iterable = None, exclude_resources: typing.Iterable = None
):
	"""
	Creates a nested 'authz' dict with tenant:resource structure:
	{
		'*': ['resourceA', 'resourceB'],
		'tenantA': ['resourceA', 'resourceB', 'resourceC'],
		'tenantB': ['resourceA', 'resourceB', 'resourceE', 'resourceD'],
	}
	"""
	exclude_resources = exclude_resources or frozenset()

	# Add global resources under "*"
	# Add tenant-specific resources under their tenant_id
	authz = {}
	for tenant in {"*", *(tenants or {})}:
		authz[tenant] = set()
		roles = await role_service.get_roles_by_credentials(credentials_id, [tenant])
		if (
			tenant != "*"
			and len(roles) == 0
			and role_service.TenantBaseRole is not None
		):
			# Integrity fix: User has no role in their assigned tenant, assign them the base role
			with local_authz(
				"build_credentials_authz",
				resources=[ResourceId.SUPERUSER],
			):
				try:
					await role_service.get(role_service.TenantBaseRole)
				except exceptions.RoleNotFoundError:
					L.warning("Tenant base role is not ready.", struct_data={"role": role_service.TenantBaseRole})
					continue
				L.log(asab.LOG_NOTICE, "Assigning base role to user with no roles in tenant.", struct_data={
					"tenant": tenant, "cid": credentials_id})
				tenant_base_role = global_role_id_to_propagated(role_service.TenantBaseRole, tenant)
				await role_service.assign_role(credentials_id, tenant_base_role)
				roles.append(tenant_base_role)

		for role in roles:
			try:
				resources = await role_service.get_role_resources(role)
			except exceptions.RoleNotFoundError:
				# Integrity fix: Detected assignment of a non-existent role, remove it
				L.log(asab.LOG_NOTICE, "Found assignment of a non-existent role.", struct_data={
					"role_id": role, "cid": credentials_id})
				with local_authz(
					"build_credentials_authz",
					resources=[ResourceId.SUPERUSER],
				):
					await role_service.unassign_role(credentials_id, role)
				continue

			for res in resources:
				if res in exclude_resources:
					continue
				authz[tenant].add(res)

	for tenant in authz:
		authz[tenant] = list(authz[tenant])

	return authz
