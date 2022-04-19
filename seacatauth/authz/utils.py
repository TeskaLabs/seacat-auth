async def get_credentials_authz(credentials_id, tenant_service, role_service):
	"""
	Creates a nested 'authz' dict with tenant:role:resource structure:
	{
		'*': {
			'*/roleB': ['resourceA', 'resourceB'],
		},
		'tenantA': {
			'tenantA/roleA': ['resourceA', 'resourceB'],
			'*/roleB': ['resourceA', 'resourceB'],
		},
		'tenantB': {
			'tenantB/roleB': ['resourceA', 'resourceB'],
			'tenantB/roleC': ['resourceE', 'resourceD'],
			'*/roleB': ['resourceA', 'resourceB'],
		},
	}
	"""

	# Add global roles and resources under "*"
	authz = {}
	tenant = "*"
	authz[tenant] = {}
	for role in await role_service.get_roles_by_credentials(credentials_id, tenant):
		authz[tenant][role] = await role_service.get_role_resources(role)

	# Add tenant-specific roles and resources if tenant service is enabled
	if tenant_service.is_enabled():
		for tenant in await tenant_service.get_tenants(credentials_id):
			authz[tenant] = {}
			for role in await role_service.get_roles_by_credentials(credentials_id, tenant):
				authz[tenant][role] = await role_service.get_role_resources(role)

	return authz
