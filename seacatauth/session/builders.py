import logging
import secrets

from .adapter import SessionAdapter
from ..authz import get_credentials_authz

#

L = logging.getLogger(__name__)

#


async def credentials_session_builder(credentials_service, credentials_id):
	credentials = await credentials_service.get(credentials_id, include=["__totp"])
	return (
		(SessionAdapter.FN.Credentials.Id, credentials_id),
		(SessionAdapter.FN.Credentials.Username, credentials.get("username")),
		(SessionAdapter.FN.Credentials.Email, credentials.get("email")),
		(SessionAdapter.FN.Credentials.Phone, credentials.get("phone")),
		(SessionAdapter.FN.Credentials.CustomData, credentials.get("data")),
		(SessionAdapter.FN.Credentials.CreatedAt, credentials.get("_c")),
		(SessionAdapter.FN.Credentials.ModifiedAt, credentials.get("_m")),
		(SessionAdapter.FN.Authentication.TOTPSet, credentials.get("__totp") not in (None, "")),
	)


async def external_login_session_builder(external_login_service, credentials_id):
	external_logins = {}
	for result in await external_login_service.list(credentials_id):
		external_logins[result["t"]] = result["s"]
	return ((SessionAdapter.FN.Authentication.ExternalLoginOptions, external_logins),)


async def authz_session_builder(tenant_service, role_service, credentials_id, tenant):
	"""
	Add 'authz' dict with currently authorized tenants and their resources
	Add 'tenants' list with complete list of credential's tenants
	"""
	return (
		(SessionAdapter.FN.Authorization.Authz, await get_credentials_authz(
			tenant_service, role_service, credentials_id, tenant)),
		(SessionAdapter.FN.Authorization.Tenants, await tenant_service.get_tenants(credentials_id)),
	)


def login_descriptor_session_builder(login_descriptor):
	if login_descriptor is not None:
		yield (SessionAdapter.FN.Authentication.LoginDescriptor, login_descriptor)


async def available_factors_session_builder(authentication_service, credentials_id):
	factors = []
	for factor in authentication_service.LoginFactors.values():
		if await factor.is_eligible({"credentials_id": credentials_id}):
			factors.append(factor.Type)
	return ((SessionAdapter.FN.Authentication.AvailableFactors, factors),)


def cookie_session_builder():
	# TODO: Shorten back to 32 bytes once unencrypted cookies are obsoleted
	token_length = 16 + 32  # The first part is AES CBC init vector, the second is the actual token
	yield (SessionAdapter.FN.Cookie.Id, secrets.token_bytes(token_length))
