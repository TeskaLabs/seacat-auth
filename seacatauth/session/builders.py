import logging
import secrets
import datetime

from ..models import Session
from ..authz import build_credentials_authz


L = logging.getLogger(__name__)


async def credentials_session_builder(credentials_service, credentials_id, scope=None):
	scope = scope or frozenset()
	credentials = await credentials_service.get(credentials_id, include=["__totp"])
	data = [
		(Session.FN.Credentials.Id, credentials_id),
		(Session.FN.Credentials.CreatedAt, credentials.get("_c")),
		(Session.FN.Credentials.ModifiedAt, credentials.get("_m")),
	]
	# "profile", "email" and "phone" are scope values defined by OIDC
	# (https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
	# The values prefixed with "userinfo:" are kept for backwards compatibility
	# TODO: Remove the "userinfo:" scope values
	if "profile" in scope or "userinfo:username" in scope or "userinfo:*" in scope:
		data.append((Session.FN.Credentials.Username, credentials.get("username")))
	if "email" in scope or "userinfo:email" in scope or "userinfo:*" in scope:
		data.append((Session.FN.Credentials.Email, credentials.get("email")))
	if "phone" in scope or "userinfo:phone" in scope or "userinfo:*" in scope:
		data.append((Session.FN.Credentials.Phone, credentials.get("phone")))
	if "profile" in scope or "userinfo:data" in scope or "userinfo:*" in scope:
		data.append((Session.FN.Credentials.CustomData, credentials.get("data")))
	if "profile" in scope or "userinfo:authn" in scope or "userinfo:*" in scope:
		data.append((Session.FN.Authentication.TOTPSet, credentials.get("__totp") not in (None, "")))
	return data


async def external_login_session_builder(external_login_service, credentials_id):
	external_logins = {}
	for result in await external_login_service.list_external_accounts(credentials_id):
		try:
			external_logins[result["type"]] = result["sub"]
		except KeyError:
			# BACK COMPAT
			external_logins[result["t"]] = result["s"]
	return ((Session.FN.Authentication.ExternalLoginOptions, external_logins),)


async def authz_session_builder(
	tenant_service, role_service, credentials_id,
	tenants=None, exclude_resources=None, show_tenant_list=False
):
	"""
	Add 'authz' dict with currently authorized tenants and their resources
	Add 'tenants' list with complete list of credential's tenants
	"""
	tenants = tenants or []
	authz = await build_credentials_authz(tenant_service, role_service, credentials_id, tenants, exclude_resources)
	if (show_tenant_list):
		user_tenants = list(set(await tenant_service.get_tenants(credentials_id)).union(tenants))
		return (
			(Session.FN.Authorization.Authz, authz),
			(Session.FN.Authorization.AssignedTenants, user_tenants),
		)
	return (
		(Session.FN.Authorization.Authz, authz),
		(Session.FN.Authorization.AssignedTenants, []),
	)


def authentication_session_builder(login_descriptor):
	yield (Session.FN.Authentication.AuthnTime, datetime.datetime.now(datetime.UTC))
	if login_descriptor is not None:
		yield (Session.FN.Authentication.LoginDescriptor, login_descriptor["id"])
		yield (Session.FN.Authentication.LoginFactors, [
			factor["type"] for factor in login_descriptor["factors"]])


async def available_factors_session_builder(authentication_service, credentials_id):
	factors = await authentication_service.get_eligible_factors(credentials_id)
	return ((Session.FN.Authentication.AvailableFactors, factors),)


def cookie_session_builder():
	# TODO: Shorten back to 32 bytes once unencrypted cookies are obsoleted
	token_length = 16 + 32  # The first part is AES CBC init vector, the second is the actual token
	yield (Session.FN.Cookie.Id, secrets.token_bytes(token_length))


def oauth2_session_builder(client_id: str, scope: frozenset | None, nonce: str = None, redirect_uri: str = None):
	yield (Session.FN.OAuth2.Scope, scope)
	yield (Session.FN.OAuth2.ClientId, client_id)
	if redirect_uri is not None:
		yield (Session.FN.OAuth2.RedirectUri, redirect_uri)
	if nonce is not None:
		yield (Session.FN.OAuth2.Nonce, nonce)
