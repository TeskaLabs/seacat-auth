import logging
import asab
import typing

from .role.view.propagated_role import global_role_id_to_propagated
from .. import exceptions
from ..api import local_authz
from ..models.const import ResourceId


L = logging.getLogger(__name__)


async def build_credentials_authz(
	tenant_service, role_service, credentials_id: str,
	tenants: typing.Iterable = None, exclude_resources: typing.Iterable = None
) -> typing.Dict[str, typing.List[str]]:
	"""
	Build authorization mapping for given credentials.

	Args:
		tenant_service: Tenant service instance.
		role_service: Role service instance.
		credentials_id: ID of the credentials to build authz for.
		tenants: Iterable of tenant IDs to build authz for. If None, only global resources are included.
		exclude_resources: Iterable of resource IDs to exclude from the result.

	Returns:
		A dictionary mapping tenant IDs to lists of resource IDs.
		Example:
			{
				'*': ['resourceA', 'resourceB'],
				'tenantA': ['resourceA', 'resourceB', 'resourceC'],
				'tenantB': ['resourceA', 'resourceB', 'resourceE', 'resourceD'],
			}
	"""
	exclude_resources = exclude_resources or frozenset()
	authz = {}

	# Explicitly gather global resources, add them to all tenants and '*'
	global_resources = set()
	global_roles = await role_service.get_roles_by_credentials(credentials_id, [None])
	for role in global_roles:
		try:
			resources = await role_service.get_role_resources(role)
			global_resources.update(res for res in resources if res not in exclude_resources)
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
	authz["*"] = list(global_resources)

	# Add tenant-specific resources under their tenant_id
	for tenant in tenants or []:
		tenant_resources = set(global_resources)
		tenant_roles = await role_service.get_roles_by_credentials(credentials_id, [tenant])

		# Gather resources from all assigned roles
		for role in tenant_roles:
			try:
				resources = await role_service.get_role_resources(role)
				tenant_resources.update(res for res in resources if res not in exclude_resources)
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

		# If no resources found, ensure at least tenant base role resources are included (if available)
		if len(tenant_resources) == 0 and role_service.TenantBaseRole is not None:
			tenant_base_role = global_role_id_to_propagated(role_service.TenantBaseRole, tenant)
			if tenant_base_role not in tenant_roles:
				with local_authz(
					"build_credentials_authz",
					resources=[ResourceId.SUPERUSER],
				):
					try:
						await role_service.assign_role(credentials_id, tenant_base_role)
						tenant_roles.append(tenant_base_role)
						resources = await role_service.get_role_resources(tenant_base_role)
						tenant_resources.update(res for res in resources if res not in exclude_resources)
					except exceptions.RoleNotFoundError:
						L.warning("Tenant base role is not ready.", struct_data={
							"role": role_service.TenantBaseRole})

		authz[tenant] = list(tenant_resources)

	return authz
