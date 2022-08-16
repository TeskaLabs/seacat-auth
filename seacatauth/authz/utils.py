async def get_credentials_authz(credentials_id, tenant_service, role_service):
	"""
	Creates a nested 'authz' dict with tenant:resource structure:
	{
		'*': {
			['resourceA', 'resourceB'],
		},
		'tenantA': {
			['resourceA', 'resourceB', 'resourceC'],
		},
		'tenantB': {
			['resourceA', 'resourceB', 'resourceE', 'resourceD'],
		},
	}
	"""

	# Add global roles and resources under "*"
	authz = {}
	tenant = "*"
	authz[tenant] = set()
	for role in await role_service.get_roles_by_credentials(credentials_id, tenant):
		authz[tenant].update(await role_service.get_role_resources(role))
	authz[tenant] = list(authz[tenant])

	# Add tenant-specific roles and resources if tenant service is enabled
	if tenant_service.is_enabled():
		# TODO: ?? Add all known tenants if the user has "authz:superuser" or "authz:tenant:access" ??
		#   Or use OIDC scope and add only tenants in scope?
		for tenant in await tenant_service.get_tenants(credentials_id):
			authz[tenant] = set()
			for role in await role_service.get_roles_by_credentials(credentials_id, tenant):
				authz[tenant].update(await role_service.get_role_resources(role))
			authz[tenant] = list(authz[tenant])

	return authz
