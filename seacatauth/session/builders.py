import logging
import secrets

from .adapter import SessionAdapter

#

L = logging.getLogger(__name__)

#


def credentials_session_builder(identity_id):
	# TODO: Include username, email, phone, maybe _c and _m
	yield (SessionAdapter.FNCredentialsId, identity_id)


async def authz_session_builder(tenant_service, role_service, credentials_id):
	"""
	Creates a "authz" attribute with the following structure:
	'authz': {
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

	return ((SessionAdapter.FNAuthz, authz),)


def login_descriptor_session_builder(login_descriptor):
	if login_descriptor is not None:
		yield (SessionAdapter.FNLoginDescriptor, login_descriptor)


async def available_factors_session_builder(authentication_service, credentials_id):
	factors = []
	for factor in authentication_service.LoginFactors.values():
		if await factor.is_eligible({"credentials_id": credentials_id}):
			factors.append(factor.ID)
	return ((SessionAdapter.FNAvailableFactors, factors), )


def cookie_session_builder():
	# TODO: Shorten back to 32 bytes once unencrypted cookies are obsoleted
	token_length = 16 + 32  # The first part is AES CBC init vector, the second is the actual token
	yield (SessionAdapter.FNCookieSessionId, secrets.token_bytes(token_length))
