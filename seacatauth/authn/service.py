import datetime
import json
import logging
import re
import urllib.parse

import asab

from .login_descriptor import LoginDescriptor
from .login_factors import login_factor_builder
from .login_session import LoginSession
from .. import exceptions, generic, AuditLogger
from ..last_activity import EventCode
from ..authz import build_credentials_authz

from ..session import (
	credentials_session_builder,
	authz_session_builder,
	authentication_session_builder,
	available_factors_session_builder,
	SessionAdapter,
)

from ..events import EventTypes

#

L = logging.getLogger(__name__)

#

LOGIN_DESCRIPTOR_FALLBACK = [
	{
		"id": "default",
		"label": "Use default login",
		"factors": [
			# If TOTP is active, two-factor login should be required by default
			[
				{"id": "password", "type": "password"},
				{"id": "totp", "type": "totp"}
			],
			[
				{"id": "password", "type": "password"}
			]
		],
	},
	{
		"id": "webauthn",
		"label": "FIDO2/WebAuthn login",
		"factors": [
			[
				{"id": "password", "type": "password"},
				{"id": "webauthn", "type": "webauthn"}
			],
		],
	},
]


class AuthenticationService(asab.Service):
	LoginSessionCollection = "ls"

	def __init__(self, app, service_name="seacatauth.AuthenticationService"):
		super().__init__(app, service_name)

		self.StorageService = app.get_service("asab.StorageService")
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.RBACService = app.get_service("seacatauth.RBACService")
		self.ResourceService = app.get_service("seacatauth.ResourceService")
		self.LastActivityService = app.get_service("seacatauth.LastActivityService")
		self.CommunicationService = app.get_service("seacatauth.CommunicationService")
		self.MetricsService = app.get_service("asab.MetricsService")

		self.LoginUrl = "{}/#/login".format(self.App.AuthWebUiUrl)

		self.CustomLoginParameters = asab.Config.get("seacatauth:authentication", "custom_login_parameters")
		if self.CustomLoginParameters != "":
			self.CustomLoginParameters = frozenset(re.split(r"\s+", self.CustomLoginParameters))
		else:
			self.CustomLoginParameters = frozenset()

		self.LoginAttempts = asab.Config.getint("seacatauth:authentication", "login_attempts")
		self.LoginSessionExpiration = datetime.timedelta(
			seconds=asab.Config.getseconds("seacatauth:authentication", "login_session_expiration"))

		self.LoginFactors = {}
		self.LoginDescriptors = None
		self.LoginDescriptorFallback = [
			LoginDescriptor.build(self, config)
			for config
			in LOGIN_DESCRIPTOR_FALLBACK
		]
		self._load_global_descriptors()

		enforce_factors = asab.Config.get("seacatauth:authentication", "enforce_factors")
		if len(enforce_factors) > 0:
			# TODO: not all factors should be allowed as the second factor
			self.EnforceFactors = enforce_factors.split(" ")
			# Check that all required factors are configured
			for factor_type in self.EnforceFactors:
				if factor_type not in self.LoginFactors:
					raise ValueError("Cannot enforce a login factor which has not been configured in login descriptors.")
		else:
			self.EnforceFactors = None

		# Metrics - login counters
		self.LoginCounter = self.MetricsService.create_counter(
			"logins",
			tags={"help": "Counts successful and failed logins per minute.", "unit": "epm"},
			init_values={"successful": 0, "failed": 0}
		)

		app.PubSub.subscribe("Application.housekeeping!", self._on_housekeeping)


	async def _on_housekeeping(self, event_name):
		await self.delete_expired_login_sessions()


	def _load_global_descriptors(self):
		descriptor_file = asab.Config.get("seacatauth:authentication", "descriptor_file")
		if descriptor_file in {None, ""}:
			# No file specified: Use fallback descriptor
			self.LoginDescriptors = self.LoginDescriptorFallback
			return
		# Load descriptors from file
		with open(descriptor_file) as f:
			descriptors_config = json.load(f)
		self.LoginDescriptors = [
			LoginDescriptor.build(self, config)
			for config
			in descriptors_config
		]


	async def create_login_session(
		self,
		credentials_id=None,
		session_id=None,
		authorization_params=None,
	):
		login_session = LoginSession(
			initiator_cid=credentials_id,
			initiator_sid=session_id,
			authorization_params=authorization_params,
		)
		upsertor = self.StorageService.upsertor(
			self.LoginSessionCollection,
			login_session.Id)
		for k, v in login_session.serialize().items():
			upsertor.set(k, v)
		await upsertor.execute()
		return login_session


	async def _upsert_login_session(self, login_session: LoginSession):
		upsertor = self.StorageService.upsertor(
			self.LoginSessionCollection,
			login_session.Id,
			version=login_session.Version)
		for k, v in login_session.serialize().items():
			upsertor.set(k, v, encrypt=k in LoginSession.EncryptedFields)
		await upsertor.execute()


	async def get_login_session(self, login_session_id):
		ls_data = await self.StorageService.get(
			self.LoginSessionCollection, login_session_id, decrypt=LoginSession.EncryptedFields)
		login_session = LoginSession.deserialize(self, ls_data)
		if login_session.Created + self.LoginSessionExpiration < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("Login session expired")
		return login_session


	async def update_login_session(self, login_session, *, data=None, login_attempts_left=None):
		upsertor = self.StorageService.upsertor(
			self.LoginSessionCollection,
			obj_id=login_session.Id,
			version=login_session.Version
		)
		if data is not None:
			upsertor.set("d", data)
		if login_attempts_left is not None:
			upsertor.set("la", login_attempts_left)

		await upsertor.execute(event_type=EventTypes.LOGIN_SESSION_UPDATED)
		L.info("Login session updated", struct_data={
			"lsid": login_session.Id,
		})
		return await self.get_login_session(login_session.Id)


	async def delete_login_session(self, login_session_id):
		await self.StorageService.delete(self.LoginSessionCollection, login_session_id)
		L.info("Login session deleted", struct_data={
			"lsid": login_session_id
		})


	async def delete_expired_login_sessions(self):
		collection = self.StorageService.Database[self.LoginSessionCollection]

		query_filter = {"exp": {"$lt": datetime.datetime.now(datetime.timezone.utc)}}
		result = await collection.delete_many(query_filter)
		if result.deleted_count > 0:
			L.info("Expired login sessions deleted", struct_data={
				"count": result.deleted_count
			})


	async def prepare_login_descriptors(self, credentials_id, request_headers, login_preferences=None):
		return await self._prepare_login_descriptors(
			self.LoginDescriptors,
			credentials_id,
			request_headers,
			login_preferences
		)

	async def prepare_fallback_login_descriptors(self, credentials_id, request_headers=None):
		login_descriptors = await self._prepare_login_descriptors(
			self.LoginDescriptorFallback,
			credentials_id,
			request_headers,
			login_preferences=None
		)
		if login_descriptors is None:
			raise Exception("Failed to prepare fallback login descriptors.")
		return login_descriptors

	async def _prepare_login_descriptors(
		self,
		login_descriptors,
		credentials_id,
		request_headers=None,
		login_preferences=None
	):
		ready_login_descriptors = []
		login_data = {
			"credentials_id": credentials_id,
			"request_headers": request_headers or {}
		}
		descriptor_factors = []
		for descriptor in login_descriptors:
			ready_descriptor = await descriptor.login_prologue(login_data, login_preferences)
			if ready_descriptor is not None:
				ready_login_descriptors.append(ready_descriptor)
				descriptor_factors.append((
					ready_descriptor,
					set(factor.Type for factor in ready_descriptor.FactorGroups[0])
				))

		# Remove descriptors whose factor_set is a subset of another descriptor's factor_set
		# This is to hide single-factor options when multi-factor options are available
		descriptor_factors.sort(key=lambda pair: len(pair[1]), reverse=True)
		i = 0
		j = len(descriptor_factors) - 1
		while i < len(descriptor_factors):
			if j <= i:
				i += 1
				j = len(descriptor_factors) - 1
				continue
			if descriptor_factors[j][1].issubset(descriptor_factors[i][1]):
				ready_login_descriptors.remove(descriptor_factors[j][0])
				descriptor_factors.pop(j)
			j -= 1

		if len(ready_login_descriptors) == 0:
			L.warning("No suitable login descriptor", struct_data={
				"credentials_id": credentials_id,
				"url_login_preferences": login_preferences
			})
			return None
		return ready_login_descriptors

	def get_login_factor(self, factor_type):
		return self.LoginFactors[factor_type]

	async def get_eligible_factors(self, credentials_id: str):
		return [
			factor.Type
			for factor in self.LoginFactors.values()
			if await factor.is_eligible({"credentials_id": credentials_id})
		]

	def create_login_factor(self, factor_config):
		self.LoginFactors[factor_config["type"]] = login_factor_builder(self, factor_config)
		return self.LoginFactors[factor_config["type"]]

	async def authenticate(self, login_session, request_data):
		"""
		Walk through factors in the requested login descriptor and try to authenticate in all of them.
		"""
		login = login_session.SeacatLogin

		# Fail if we have a fake login session
		if login.CredentialsId == "":
			L.log(asab.LOG_NOTICE, "Login failed: Fake login session", struct_data={"lsid": login_session.Id})
			return False

		# First make sure that the user is not suspended
		credentials = await self.CredentialsService.get(login.CredentialsId, include=frozenset(["suspended"]))
		if credentials.get("suspended") is True:
			L.warning(
				"Login failed: User suspended",
				struct_data={"cid": login.CredentialsId}
			)
			return False

		authenticated = False
		for descriptor in login.LoginDescriptors:
			# Find the descriptor that matches the one in request_data
			if descriptor.ID != request_data["descriptor"]:
				continue

			# All factors in a descriptor must pass for the descriptor to pass
			authenticated = await descriptor.authenticate(login, request_data)
			if authenticated:
				login.AuthenticatedVia = descriptor.serialize()
				L.log(
					asab.LOG_NOTICE,
					"User authenticated by descriptor '{}'".format(descriptor.ID),
					struct_data={"cid": login.CredentialsId}
				)
				break
		return authenticated


	async def login(self, login_session, root_session: SessionAdapter | None = None, from_info: list = None):
		"""
		Build and create an SSO root session
		"""
		session_builders = await self.SessionService.build_sso_root_session(
			credentials_id=login_session.SeacatLogin.CredentialsId,
			login_descriptor=login_session.SeacatLogin.AuthenticatedVia,
		)
		if root_session and not root_session.is_anonymous():
			# Update existing SSO root session (re-login)
			assert root_session.Session.Type == "root"
			assert root_session.Credentials.Id == login_session.SeacatLogin.CredentialsId
			new_sso_session = await self.update_session(
				root_session.SessionId,
				session_builders=session_builders
			)
		else:
			# Create a new root session
			new_sso_session = await self.create_session(
				session_type="root",
				session_builders=session_builders,
			)

		AuditLogger.log(asab.LOG_NOTICE, "Authentication successful", struct_data={
			"cid": login_session.SeacatLogin.CredentialsId,
			"lsid": login_session.Id,
			"sid": str(new_sso_session.Session.Id),
			"from_ip": from_info,
		})
		await self.LastActivityService.update_last_activity(
			EventCode.LOGIN_SUCCESS, login_session.SeacatLogin.CredentialsId, from_ip=from_info)

		# Delete login session
		await self.delete_login_session(login_session.Id)

		return new_sso_session


	async def create_m2m_session(
		self,
		credentials_id: str,
		login_descriptor: dict,
		session_expiration: float = None,
		from_info: list = None
	):
		"""
		Direct authentication for M2M access (without login sessions)
		This is NOT OpenIDConnect/OAuth2 compliant!
		"""
		# TODO: Get tenant, scope and other necessary OIDC info from credentials
		scope = frozenset(["tenant:*", "profile", "email"])
		authz = await build_credentials_authz(self.TenantService, self.RoleService, credentials_id)
		has_access_to_all_tenants = self.RBACService.can_access_all_tenants(authz)
		tenants = await self.TenantService.get_tenants_by_scope(
			scope, credentials_id, has_access_to_all_tenants)

		session_builders = [
			await credentials_session_builder(self.CredentialsService, credentials_id, scope),
			await authz_session_builder(
				tenant_service=self.TenantService,
				role_service=self.RoleService,
				credentials_id=credentials_id,
				tenants=tenants,
			),
			authentication_session_builder(login_descriptor),
			await available_factors_session_builder(self, credentials_id)
		]

		session = await self.SessionService.create_session(
			session_type="m2m",
			expiration=session_expiration,
			session_builders=session_builders,
		)

		return session


	async def create_impersonated_session(self, impersonator_session, target_cid: str):
		"""
		Create a new root session as a different user. Equivalent to logging in as the target user.
		"""
		impersonator_cid = impersonator_session.Credentials.Id

		# Check if target exists
		try:
			await self.CredentialsService.get(target_cid)
		except KeyError:
			L.log(asab.LOG_NOTICE, "Impersonation target does not exist.", struct_data={
				"impersonator_cid": impersonator_cid, "target_cid": target_cid})
			raise exceptions.CredentialsNotFoundError(target_cid)

		# Make sure that the target is not a superuser
		target_authz = await build_credentials_authz(
			self.TenantService, self.RoleService, target_cid, tenants=None)
		if self.RBACService.is_superuser(target_authz):
			L.log(
				asab.LOG_NOTICE,
				"Impersonation target is a superuser. Resource 'authz:superuser' will be excluded "
				"from the impersonated session's authorization scope.",
				struct_data={"impersonator_cid": impersonator_cid, "target_cid": target_cid})

		session_builders = await self.SessionService.build_sso_root_session(
			credentials_id=target_cid,
			# Use default login descriptor
			login_descriptor={
				"id": "default",
				"factors": [{"id": "password", "type": "password"}]
			},
		)
		session_builders.append((
			(SessionAdapter.FN.Authentication.ImpersonatorCredentialsId, impersonator_cid),
			(SessionAdapter.FN.Authentication.ImpersonatorSessionId, impersonator_session.SessionId),
		))

		session = await self.SessionService.create_session(
			session_type="root",
			session_builders=session_builders,
		)

		return session


	async def prepare_seacat_login_url(self, client_id: str, authorization_query: dict):
		"""
		Build login URI of Seacat Auth login page with callback to authorization request
		"""
		oidc_svc = self.App.get_service("seacatauth.OpenIdConnectService")
		client_svc = self.App.get_service("seacatauth.ClientService")
		client_dict = await client_svc.get(client_id)

		# Remove "prompt" and "acr_values" from callback
		prompt = authorization_query.pop("prompt", None)
		acr_values = authorization_query.pop("acr_values", None)

		# Build callback authorization URL
		authorization_url = "{}?{}".format(
			oidc_svc.authorization_endpoint_url(),
			urllib.parse.urlencode(authorization_query))

		# Prepare login params
		login_query_params = [
			("redirect_uri", authorization_url),
			("client_id", client_id)]
		if prompt:
			login_query_params.append(("prompt", prompt))
		if acr_values:
			login_query_params.append(("acr_values", acr_values))

		login_url = client_dict.get("login_uri")
		if login_url is None:
			login_url = self.LoginUrl

		parsed = generic.urlparse(login_url)
		if parsed["fragment"] != "":
			# If the Login URI contains fragment, add the login params into the fragment query
			fragment_parsed = generic.urlparse(parsed["fragment"])
			query = urllib.parse.parse_qs(fragment_parsed["query"])
			query.update(login_query_params)
			fragment_parsed["query"] = urllib.parse.urlencode(query)
			parsed["fragment"] = generic.urlunparse(**fragment_parsed)
		else:
			# If the Login URI contains no fragment, add the login params into the regular URL query
			query = urllib.parse.parse_qs(parsed["query"])
			query.update(login_query_params)
			parsed["query"] = urllib.parse.urlencode(query)

		return generic.urlunparse(**parsed)


	async def prepare_seacat_login(
		self,
		login_session: str | LoginSession,
		ident: str,
		client_public_key,
		request_headers: dict | None = None,
		login_dict: dict | None = None,
		login_preferences: list | None = None,
	) -> LoginSession:
		"""
		Set up login session with located credentials and prepare login options
		"""
		if isinstance(login_session, str):
			login_session = await self.get_login_session(login_session)

		# Locate credentials
		credentials_id = await self.CredentialsService.locate(ident, stop_at_first=True, login_dict=login_dict)

		if credentials_id is None or credentials_id == []:
			L.log(asab.LOG_NOTICE, "Cannot locate credentials", struct_data={"ident": ident})
			raise exceptions.LoginPrologueDeniedError("Unmatched ident")
		elif credentials_id.startswith("m2m:"):
			# Deny login to m2m credentials
			L.log(asab.LOG_NOTICE, "Cannot login with machine credentials", struct_data={
				"cid": credentials_id})
			raise exceptions.LoginPrologueDeniedError("Cannot login with M2M credentials")

		credentials = await self.CredentialsService.get(credentials_id)
		if credentials.get("suspended") is True:
			# Deny login to suspended credentials
			L.warning("Login denied to suspended credentials", struct_data={"cid": credentials_id})
			raise exceptions.LoginPrologueDeniedError("Cannot login with suspended credentials")

		login_descriptors = await self.prepare_login_descriptors(
			credentials_id=credentials_id,
			request_headers=request_headers,
			login_preferences=login_preferences
		)
		if login_descriptors is None:
			L.log(asab.LOG_NOTICE, "No suitable login descriptor", struct_data={
				"cid": credentials_id, "ldid": login_preferences})
			raise exceptions.LoginPrologueDeniedError("No suitable login descriptor")

		login_session.initialize_seacat_login(
			ident=ident,
			credentials_id=credentials_id,
			login_descriptors=login_descriptors,
			login_attempts_left=self.LoginAttempts,
			client_login_key=client_public_key
		)
		await self._upsert_login_session(login_session)
		L.log(asab.LOG_NOTICE, "Login session prepared", struct_data={
			"cid": credentials_id, "ident": ident, "id": login_session.Id})
		return login_session


	async def prepare_failed_seacat_login(
		self,
		login_session: str | LoginSession,
		ident: str, client_public_key
	) -> LoginSession:
		"""
		Set up the login session so that the login call is guaranteed to fail
		"""
		if isinstance(login_session, str):
			login_session = await self.get_login_session(login_session)

		login_descriptors = await self.prepare_fallback_login_descriptors(credentials_id="")
		login_session.initialize_seacat_login(
			ident=ident,
			credentials_id="",
			login_descriptors=login_descriptors,
			login_attempts_left=self.LoginAttempts,
			client_login_key=client_public_key
		)
		await self._upsert_login_session(login_session)
		L.log(asab.LOG_NOTICE, "Failed login session prepared", struct_data={
			"ident": ident, "id": login_session.Id})
		return login_session
