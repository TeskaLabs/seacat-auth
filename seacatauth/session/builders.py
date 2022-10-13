import logging
import secrets

from .adapter import SessionAdapter
from ..authz import build_credentials_authz

#

L = logging.getLogger(__name__)

#


async def credentials_session_builder(credentials_service, credentials_id, scope=None):
	scope = scope or frozenset()
	credentials = await credentials_service.get(credentials_id, include=["__totp"])
	data = [
		(SessionAdapter.FN.Credentials.Id, credentials_id),
		(SessionAdapter.FN.Credentials.CreatedAt, credentials.get("_c")),
		(SessionAdapter.FN.Credentials.ModifiedAt, credentials.get("_m")),
	]
	if "userinfo:username" in scope or "userinfo:*" in scope:
		data.append((SessionAdapter.FN.Credentials.Username, credentials.get("username")))
	if "userinfo:email" in scope or "userinfo:*" in scope:
		data.append((SessionAdapter.FN.Credentials.Email, credentials.get("email")))
	if "userinfo:phone" in scope or "userinfo:*" in scope:
		data.append((SessionAdapter.FN.Credentials.Phone, credentials.get("phone")))
	if "userinfo:data" in scope or "userinfo:*" in scope:
		data.append((SessionAdapter.FN.Credentials.CustomData, credentials.get("data")))
	if "userinfo:authn" in scope or "userinfo:*" in scope:
		data.append((SessionAdapter.FN.Authentication.TOTPSet, credentials.get("__totp") not in (None, "")))
	return data


async def external_login_session_builder(external_login_service, credentials_id):
	external_logins = {}
	for result in await external_login_service.list(credentials_id):
		external_logins[result["t"]] = result["s"]
	return ((SessionAdapter.FN.Authentication.ExternalLoginOptions, external_logins),)


async def authz_session_builder(tenant_service, role_service, credentials_id, tenants=None):
	"""
	Add 'authz' dict with currently authorized tenants and their resources
	Add 'tenants' list with complete list of credential's tenants
	"""
	tenants = tenants or []
	authz = await build_credentials_authz(tenant_service, role_service, credentials_id, tenants)
	user_tenants = list(set(await tenant_service.get_tenants(credentials_id)).union(tenants))
	return (
		(SessionAdapter.FN.Authorization.Authz, authz),
		(SessionAdapter.FN.Authorization.Tenants, user_tenants),
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
