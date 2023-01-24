import asab.exceptions


async def list_assigned_credential_ids(tenant_service, role_service, filter):
	if "has_tenant" in filter:
		tenant = filter["has_tenant"]
		provider = tenant_service.get_provider()
		assignments = await provider.list_tenant_assignments(tenant)
	elif "has_role" in filter:
		role = filter["has_role"]
		assignments = await role_service.list_role_assignments(role)
	else:
		raise asab.exceptions.ValidationError("Unsupported filter: {!r}".format(filter))

	return set(a["c"] for a in assignments["data"])