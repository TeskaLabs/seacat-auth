import random


async def add_to_header(headers, what, session, credentials_service, requested_tenant=None):
	'''
	Prepare a common header with:
	* X-Credentials: htpasswd:id:foobar
	* X-Username: foobar
	* X-Tenants: tenant1 tenant2 tenant3
	* X-Roles: role1 role2 role3
	* X-Resources: resource1 resource2 resource3
	'''

	# obtain username to append add in headers
	if "credentials" in what:
		credentials = await credentials_service.get(session.CredentialsId)
		headers["X-Credentials"] = credentials["_id"]
		v = credentials.get("username")
		if v is not None:
			headers["X-Username"] = v

	# Obtain assigned tenants from session object
	if "tenants" in what:
		tenants = [tenant for tenant in session.Authz.keys() if tenant != "*"]
		if len(tenants) > 0:
			headers["X-Tenants"] = " ".join(tenants)

	# Obtain assigned roles from session object
	if "roles" in what:
		# Add only global roles if no tenant was requested
		if requested_tenant is None:
			roles = session.Authz["*"].keys()
		else:
			roles = session.Authz[requested_tenant].keys()
		headers["X-Roles"] = " ".join(roles)

	# Obtain assigned resources from session object
	if "resources" in what:
		if requested_tenant is None:
			resources = session.Authz["*"].values()
		else:
			resources = session.Authz[requested_tenant].values()
		headers["X-Resources"] = " ".join(set(sum(resources, [])))

	# Obtain login factors from session object
	if "factors" in what:
		if session.LoginDescriptor is not None:
			factors = [
				factor["id"]
				for factor
				in session.LoginDescriptor["factors"]
			]
			headers["X-Login-Factors"] = " ".join(factors)

	# Obtain login descriptor IDs from session object
	if "ldid" in what:
		if session.LoginDescriptor is not None:
			headers["X-Login-Descriptor"] = session.LoginDescriptor["id"]

	return headers


def generate_ergonomic_token(length: int):
	'''
	This function generates random string that is "ergonomic".
	This means that it contains only the letters and numbers that are unlikely to be misread by people.
	'''
	assert(length >= 1)
	return ''.join(random.choice(ergonomic_characters) for _ in range(length))


# These are characters that are safe (prevents confusion with other characters)
ergonomic_characters = "23456789abcdefghjkmnpqrstuvxyz"
