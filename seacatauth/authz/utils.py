async def get_credentials_authz(tenant_service, role_service, credentials_id, tenant):
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
	authz["*"] = set()
	for role in await role_service.get_roles_by_credentials(credentials_id, "*"):
		authz["*"].update(await role_service.get_role_resources(role))
	authz["*"] = list(authz["*"])

	# Add tenant-specific roles and resources
	if tenant_service.is_enabled() and tenant is not None:
		authz[tenant] = set()
		for role in await role_service.get_roles_by_credentials(credentials_id, tenant):
			authz[tenant].update(await role_service.get_role_resources(role))
		authz[tenant] = list(authz[tenant])

	return authz
