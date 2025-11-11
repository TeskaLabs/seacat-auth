import typing
import logging

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

	# Add global roles and resources under "*"
	authz = {}
	tenant = "*"
	authz[tenant] = set()
	for role in await role_service.get_roles_by_credentials(credentials_id, [tenant]):
		try:
			resources = await role_service.get_role_resources(role)
		except exceptions.RoleNotFoundError:
			# Integrity fix: Detected assignment of a non-existent role, remove it
			L.warning("Integrity error: Found assignment of a non-existent role.", struct_data={
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

	authz[tenant] = list(authz[tenant])

	# Add tenant-specific roles and resources
	if tenants is not None:
		for tenant in tenants:
			authz[tenant] = set()
			for role in await role_service.get_roles_by_credentials(credentials_id, [tenant]):
				authz[tenant].update(
					res
					for res in await role_service.get_role_resources(role)
					if res not in exclude_resources
				)
			authz[tenant] = list(authz[tenant])

	return authz
