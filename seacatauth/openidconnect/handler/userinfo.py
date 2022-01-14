import logging

import aiohttp
import aiohttp.web

import asab
import asab.web.rest

#

L = logging.getLogger(__name__)

#


class UserInfoHandler(object):


	def __init__(self, app, oidc_svc, credentials_svc, session_svc, tenant_service, role_service):
		self.OpenIdConnectService = oidc_svc
		self.CredentialsService = credentials_svc
		self.SessionService = session_svc
		self.TenantService = tenant_service
		self.RoleService = role_service
		self.AuditService = app.get_service("seacatauth.AuditService")

		web_app = app.WebContainer.WebApp
		# The Client sends the UserInfo Request using either HTTP GET or HTTP POST.
		web_app.router.add_get('/openidconnect/userinfo', self.userinfo)
		web_app.router.add_post('/openidconnect/userinfo', self.userinfo)

		# Public endpoints
		web_app_public = app.PublicWebContainer.WebApp
		web_app_public.router.add_get('/openidconnect/userinfo', self.userinfo)
		web_app_public.router.add_post('/openidconnect/userinfo', self.userinfo)


	async def userinfo(self, request):
		"""
		OpenID Connect Core 1.0, chapter 5.3. UserInfo Endpoint
		"""

		session = request.Session
		if session is None:
			L.warning("Request for invalid/expired session")
			return self.error_response("invalid_session", "The access token is invalid/expired.")

		# # if authorized get provider for this identity
		try:
			credentials = await self.CredentialsService.get(session.CredentialsId, include=frozenset(["__totp"]))

		except KeyError:
			L.warning("Invalid credetials", struct_data={'sid': session.CredentialsId})
			return self.error_response("invalid_credentials", "Invalid credentials.")

		except Exception:
			L.exception("Invalid credetials")
			return self.error_response("invalid_credentials", "Invalid credentials.")

		# TODO: OpenID Connect Core 1.0, chapter 5.1. Standard Claims
		userinfo = {
			'sub': session.CredentialsId,  # The sub (subject) Claim MUST always be returned in the UserInfo Response.
		}

		v = credentials.get("username")
		if v is not None:
			userinfo['preferred_username'] = v

		v = credentials.get("email")
		if v is not None:
			userinfo['email'] = v

		v = credentials.get("phone")
		if v is not None:
			userinfo['phone_number'] = v

		v = credentials.get("_m")
		if v is not None:
			userinfo['updated_at'] = v

		v = credentials.get("__totp")
		# TODO: Use OTPService or TOTPFactor to get this information
		if v is not None and len(v) > 0:
			userinfo["totp_set"] = True

		# TODO: last password change

		# Get last successful and failed login times
		try:
			last_login = await self.AuditService.get_last_logins(session.CredentialsId)
		except Exception as e:
			last_login = None
			L.warning("Could not fetch last logins: {}".format(e))

		if last_login is not None:
			if "fat" in last_login:
				userinfo["last_failed_login"] = last_login["fat"]
			if "sat" in last_login:
				userinfo["last_successful_login"] = last_login["sat"]

		userinfo['exp'] = "{}Z".format(session.Expiration.isoformat())

		userinfo['available_factors'] = session.AvailableFactors

		if session.LoginDescriptor is not None:
			userinfo['ldid'] = session.LoginDescriptor["id"]
			userinfo['factors'] = [
				factor["id"]
				for factor
				in session.LoginDescriptor["factors"]
			]

		# List enabled external login providers
		accounts = credentials.get("external_login")
		if accounts is not None:
			userinfo["external_login_enabled"] = [
				account_type
				for account_type, account_id in accounts.items()
				if len(account_id) > 0
			]

		if self.TenantService.is_enabled():
			# Include "tenants" section, list ALL of user's tenants (excluding "*")
			tenants = [t for t in session.Authz.keys() if t != "*"]
			if tenants is not None:
				userinfo["tenants"] = tenants
		else:
			tenants = None

		query_tenant = request.query.get("tenant", "*")
		# If tenant is missing or unknown, consider only global roles and resources
		if query_tenant not in session.Authz:
			L.warning("Request for unknown tenant '{}', defaulting to '*'.".format(query_tenant))
			query_tenant = "*"

		# Include "roles" and "resources" sections, with items relevant to query_tenant
		session_roles = session.Authz.get(query_tenant)
		if session_roles is not None:
			roles = []
			resources = set()
			for session_role, session_resources in session_roles.items():
				roles.append(session_role)
				resources.update(session_resources)
			if len(roles) > 0:
				userinfo["roles"] = roles
			if len(resources) > 0:
				userinfo["resources"] = list(resources)
		else:
			L.error(
				"Tenant '{}' not found in session.Authz.".format(query_tenant),
				struct_data={
					"sid": session.SessionId,
					"cid": session.CredentialsId,
					"authz": session.Authz.keys()
				}
			)

		return asab.web.rest.json_response(request, userinfo)


	def error_response(self, error, error_description):
		"""
		OpenID Connect Core 1.0, 5.3.3. Error Response
		"""
		return aiohttp.web.Response(headers={
			"WWW-Authenticate": "error=\"{}\", error_description=\"{}\"".format(error, error_description)
		}, status=401)
