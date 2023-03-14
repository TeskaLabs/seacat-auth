import datetime
import json
import logging

import asab

from .login_descriptor import LoginDescriptor
from .login_factors import login_factor_builder
from .login_session import LoginSession
from ..audit import AuditCode

from ..session import (
	credentials_session_builder,
	authz_session_builder,
	cookie_session_builder,
	login_descriptor_session_builder,
	available_factors_session_builder,
	external_login_session_builder, SessionAdapter,
)

from ..events import EventTypes

#

L = logging.getLogger(__name__)

#

LOGIN_DESCRIPTOR_FALLBACK = [
	{
		'id': 'default',
		'label': 'Use default login',
		'factors': [
			# If TOTP is active, two-factor login should be required by default
			[
				{'id': 'password', 'type': 'password'},
				{'id': 'totp', 'type': 'totp'}
			],
			[
				{'id': 'password', 'type': 'password'}
			]
		],
	},
	{
		'id': 'webauthn',
		'label': 'FIDO2/WebAuthn login',
		'factors': [
			[
				{'id': 'password', 'type': 'password'},
				{'id': 'webauthn', 'type': 'webauthn'}
			],
		],
	},
]


class AuthenticationService(asab.Service):
	# TODO: Introduce configurable LoginSession provider (MongoDB x in-memory dict)
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
		self.AuditService = app.get_service("seacatauth.AuditService")
		self.CommunicationService = app.get_service("seacatauth.CommunicationService")
		self.MetricsService = app.get_service("asab.MetricsService")

		self.LoginAttempts = asab.Config.getint("seacatauth:authentication", "login_attempts")
		self.LoginSessionExpiration = asab.Config.getseconds("seacatauth:authentication", "login_session_expiration")

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

		self.App.PubSub.subscribe("Application.tick/60!", self._on_tick)


	async def _on_tick(self, event_name):
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
		credentials_id,
		client_public_key,
		ident,
		login_descriptors=None,
		requested_session_expiration=None,
		data=None,
	):
		# Prepare the login session
		login_session = LoginSession.build(
			client_login_key=client_public_key,
			credentials_id=credentials_id,
			ident=ident,
			login_descriptors=login_descriptors,
			login_attempts=self.LoginAttempts,
			timeout=self.LoginSessionExpiration,
			requested_session_expiration=requested_session_expiration,
			data=data,
		)

		upsertor = self.StorageService.upsertor(self.LoginSessionCollection, login_session.Id)

		for k, v in login_session.serialize().items():
			upsertor.set(k, v)

		await upsertor.execute(custom_data={EventTypes.EVENT_TYPE: EventTypes.LOGIN_SESSION_CREATED})

		return login_session


	async def get_login_session(self, login_session_id):
		ls_data = await self.StorageService.get(self.LoginSessionCollection, login_session_id)
		login_session = LoginSession.deserialize(self, ls_data)
		if login_session.ExpiresAt < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("Login session expired")
		return login_session


	async def update_login_session(self, login_session_id, *, data=None, remaining_login_attempts=None):
		ls_data = await self.StorageService.get(self.LoginSessionCollection, login_session_id)
		if ls_data["exp"] < datetime.datetime.now(datetime.timezone.utc):
			raise KeyError("Login session expired")

		upsertor = self.StorageService.upsertor(
			self.LoginSessionCollection,
			obj_id=login_session_id,
			version=ls_data["_v"]
		)
		if data is not None:
			upsertor.set("d", data)
		if remaining_login_attempts is not None:
			upsertor.set("la", remaining_login_attempts)

		await upsertor.execute(custom_data={EventTypes.EVENT_TYPE: EventTypes.LOGIN_SESSION_UPDATED})
		L.info("Login session updated", struct_data={
			"lsid": login_session_id,
		})
		return True


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

	async def prepare_fallback_login_descriptors(self, credentials_id, request_headers):
		return await self._prepare_login_descriptors(
			self.LoginDescriptorFallback,
			credentials_id,
			request_headers,
			login_preferences=None
		)

	async def _prepare_login_descriptors(self, login_descriptors, credentials_id, request_headers, login_preferences=None):
		ready_login_descriptors = []
		login_data = {
			"credentials_id": credentials_id,
			"request_headers": request_headers
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

	def create_login_factor(self, factor_config):
		self.LoginFactors[factor_config["type"]] = login_factor_builder(self, factor_config)
		return self.LoginFactors[factor_config["type"]]

	async def authenticate(self, login_session, request_data):
		"""
		Walk through factors in the requested login descriptor and try to authenticate in all of them.
		"""
		# Fail if we have a fake login session
		if login_session.CredentialsId == "":
			L.warning("Login failed: Fake login session")
			return False

		# First make sure that the user is not suspended
		credentials = await self.CredentialsService.get(login_session.CredentialsId, include=frozenset(["suspended"]))
		if credentials.get("suspended") is True:
			L.warning(
				"Login failed: User suspended",
				struct_data={"cid": login_session.CredentialsId}
			)
			return False

		authenticated = False
		for descriptor in login_session.LoginDescriptors:
			# Find the descriptor that matches the one in request_data
			if descriptor.ID != request_data["descriptor"]:
				continue

			# All factors in a descriptor must pass for the descriptor to pass
			authenticated = await descriptor.authenticate(login_session, request_data)
			if authenticated:
				login_session.AuthenticatedVia = descriptor.serialize()
				L.log(
					asab.LOG_NOTICE,
					"User authenticated by descriptor '{}'".format(descriptor.ID),
					struct_data={"cid": login_session.CredentialsId}
				)
				break
		return authenticated

	async def login(self, login_session, from_info: list = None, track_id=None):
		# TODO: Move this to LoginService
		scope = frozenset(["profile", "email", "phone"])

		ext_login_svc = self.App.get_service("seacatauth.ExternalLoginService")
		session_builders = [
			await credentials_session_builder(self.CredentialsService, login_session.CredentialsId, scope),
			await authz_session_builder(
				tenant_service=self.TenantService,
				role_service=self.RoleService,
				credentials_id=login_session.CredentialsId,
				tenants=None  # Root session is tenant-agnostic
			),
			login_descriptor_session_builder(login_session.AuthenticatedVia),
			cookie_session_builder(),
			await available_factors_session_builder(self, login_session.CredentialsId),
			await external_login_session_builder(ext_login_svc, login_session.CredentialsId),
		]

		session = await self.SessionService.create_session(
			session_type="root",
			expiration=login_session.RequestedSessionExpiration,
			session_builders=session_builders,
			track_id=track_id,  # add link to previous session
		)
		L.log(
			asab.LOG_NOTICE,
			"Authentication/login successful.",
			struct_data={
				"cid": login_session.CredentialsId,
				"sid": str(session.Session.Id),
				"fi": from_info,
			}
		)

		# Add an audit entry
		await self.AuditService.append(
			AuditCode.LOGIN_SUCCESS,
			{
				"cid": login_session.CredentialsId,
				"sid": str(session.Session.Id),
				"fi": from_info,
			}
		)

		# Delete login session
		await self.delete_login_session(login_session.Id)

		return session


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
		tenants = None
		scope = frozenset(["tenant:*", "profile", "email"])

		session_builders = [
			await credentials_session_builder(self.CredentialsService, credentials_id, scope),
			await authz_session_builder(
				tenant_service=self.TenantService,
				role_service=self.RoleService,
				credentials_id=credentials_id,
				tenants=tenants,
			),
			login_descriptor_session_builder(login_descriptor),
			await available_factors_session_builder(self, credentials_id)
		]

		session = await self.SessionService.create_session(
			session_type="m2m",
			expiration=session_expiration,
			session_builders=session_builders,
		)
		L.log(
			asab.LOG_NOTICE,
			"M2M authentication successful.",
			struct_data={
				"cid": credentials_id,
				"sid": str(session.Session.Id),
				"fi": from_info,
			}
		)

		# Add an audit entry
		await self.AuditService.append(
			AuditCode.M2M_AUTHENTICATION_SUCCESSFUL,
			{
				'cid': credentials_id,
				'sid': str(session.Session.Id),
				'fi': from_info,
			}
		)

		return session


	async def create_anonymous_session(
		self,
		credentials_id: str,
		session_expiration: float = None,
		from_info: list = None
	):
		"""
		Create anonymous session for unauthenticated access
		"""
		authz_builder = await authz_session_builder(
			tenant_service=self.TenantService,
			role_service=self.RoleService,
			credentials_id=credentials_id
		)
		session_builders = [
			await credentials_session_builder(self.CredentialsService, credentials_id),
			authz_builder,
			cookie_session_builder(),
			await available_factors_session_builder(self, credentials_id),
			((SessionAdapter.FN.Authentication.IsAnonymous, True),)
		]

		session = await self.SessionService.create_session(
			session_type="root",
			expiration=session_expiration,
			session_builders=session_builders,
		)
		L.log(
			asab.LOG_NOTICE,
			"Anonymous session created.",
			struct_data={
				"cid": credentials_id,
				"sid": str(session.Session.Id),
				"fi": from_info,
			}
		)

		# Add an audit entry
		await self.AuditService.append(
			AuditCode.ANONYMOUS_SESSION_CREATED,
			{
				"cid": credentials_id,
				"sid": str(session.Session.Id),
				"fi": from_info,
			}
		)

		return session
