async def build_credentials_authz(
	tenant_service, role_service, credentials_id,
	tenants=None, exclude_resources=frozenset()
):
	"""
	Creates a nested 'authz' dict with tenant:resource structure:
	{
		'*': ['resourceA', 'resourceB'],
		'tenantA': ['resourceA', 'resourceB', 'resourceC'],
		'tenantB': ['resourceA', 'resourceB', 'resourceE', 'resourceD'],
	}
	"""
	# Add global roles and resources under "*"
	authz = {}
	tenant = "*"
	authz[tenant] = set()
	for role in await role_service.get_roles_by_credentials(credentials_id, [tenant]):
		authz[tenant].update(
			res
			for res in await role_service.get_role_resources(role)
			if res not in exclude_resources
		)
	authz[tenant] = list(authz[tenant])

	# Add tenant-specific roles and resources
	if tenant_service.is_enabled() and tenants is not None:
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
