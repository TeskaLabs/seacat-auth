import datetime
import json
import logging

import asab

from .login_descriptor import LoginDescriptor
from .login_factors import login_factor_builder
from ..audit import AuditCode
from ..session import credentials_session_builder
from ..session import authz_session_builder
from ..session import cookie_session_builder
from ..session import login_descriptor_session_builder
from ..session import available_factors_session_builder
from .login_session import LoginSession
from ..openidconnect.session import oauth2_session_builder

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

	def __init__(self, app, service_name='seacatauth.AuthenticationService'):
		super().__init__(app, service_name)

		self.SessionService = app.get_service('seacatauth.SessionService')
		self.CredentialsService = app.get_service('seacatauth.CredentialsService')
		self.TenantService = app.get_service('seacatauth.TenantService')
		self.RoleService = app.get_service('seacatauth.RoleService')
		self.ResourceService = app.get_service('seacatauth.ResourceService')
		self.AuditService = app.get_service('seacatauth.AuditService')
		self.CommunicationService = app.get_service('seacatauth.CommunicationService')
		self.MetricsService = app.get_service('asab.MetricsService')

		self.LoginAttempts = asab.Config.getint("seacatauth:authentication", "login_attempts")
		self.LoginSessionExpiration = asab.Config.getseconds("seacatauth:authentication", "login_session_expiration")

		self.LoginDescriptors = None
		self.LoginFactors = {}
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

		# TODO: introduce LoginSession providers
		self.LoginSessions = {}

		# Metrics - login counters
		self.LoginCounter = self.MetricsService.create_counter(
			"logins",
			tags={"help": "Counts successful and failed logins per minute.", "unit": "epm"},
			init_values={"successful": 0, "failed": 0}
		)

		self.App.PubSub.subscribe("Application.tick/10!", self._on_tick)

	async def _on_tick(self, event_name):
		await self.delete_expired_sessions()

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
		login_descriptors=None
	):
		# Prepare the login session
		login_session = LoginSession(
			client_login_key=client_public_key,
			credentials_id=credentials_id,
			login_descriptors=login_descriptors,
			login_attempts=self.LoginAttempts,
			login_expiration=self.LoginSessionExpiration
		)

		self.LoginSessions[login_session.Id] = login_session

		return login_session

	async def get_login_session(self, login_session_id):
		return self.LoginSessions[login_session_id]

	async def delete_login_session(self, login_session_id):
		if login_session_id in self.LoginSessions:
			L.info("Login session deleted", struct_data={
				"lsid": login_session_id
			})
			del self.LoginSessions[login_session_id]

	async def delete_expired_sessions(self):
		delete_ids = []
		for lsid, session in self.LoginSessions.items():
			if session.ExpiresAt <= datetime.datetime.utcnow():
				delete_ids.append(lsid)
		for lsid in delete_ids:
			await self.delete_login_session(lsid)

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

	def get_login_factor(self, factor_id):
		return self.LoginFactors.get(factor_id)

	def create_login_factor(self, factor_config):
		self.LoginFactors[factor_config["id"]] = login_factor_builder(self, factor_config)
		return self.LoginFactors[factor_config["id"]]

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

	async def login(self, login_session, from_info: list = None):
		# TODO: Move this to LoginService
		builders = [
			credentials_session_builder(login_session.CredentialsId),
			await authz_session_builder(
				tenant_service=self.TenantService,
				role_service=self.RoleService,
				credentials_id=login_session.CredentialsId
			),
			login_descriptor_session_builder(login_session.AuthenticatedVia),
			cookie_session_builder(),
			await available_factors_session_builder(self, login_session.CredentialsId)
		]

		# TODO: if 'openid' in scope
		oauth2_data = {
			"scope": ["openid"]  # TODO: Get actual scope
		}
		builders.append(oauth2_session_builder(oauth2_data))

		session = await self.SessionService.create_session(
			builders,
			expiration=login_session.Data.get('requested_session_expiration'),
		)
		L.log(
			asab.LOG_NOTICE,
			"Authentication/login successful.",
			struct_data={
				'cid': login_session.CredentialsId,
				'sid': str(session.SessionId),
				'fi': from_info,
			}
		)

		# Add an audit entry
		# TODO: Add the IP address
		await self.AuditService.append(
			AuditCode.LOGIN_SUCCESS,
			{
				'cid': login_session.CredentialsId,
				'sid': str(session.SessionId),
				'fi': from_info,
			}
		)

		# Delete login session
		await self.delete_login_session(login_session.Id)

		return session


	async def m2m_login(
		self,
		credentials_id: str,
		login_descriptor: LoginDescriptor,
		session_expiration: float = None,
		from_info: list = None
	):
		"""
		Direct authentication for M2M access (without login sessions)
		This is NOT OpenIDConnect/OAuth2 compliant!
		"""
		builders = [
			credentials_session_builder(credentials_id),
			await authz_session_builder(
				tenant_service=self.TenantService,
				role_service=self.RoleService,
				credentials_id=credentials_id
			),
			# login_descriptor_session_builder(login_descriptor),  # TODO: Add login descriptor
			cookie_session_builder(),
			await available_factors_session_builder(self, credentials_id)
		]

		# TODO: if 'openid' in scope
		oauth2_data = {
			"scope": ["openid"]  # TODO: Get actual scope
		}
		builders.append(oauth2_session_builder(oauth2_data))

		session = await self.SessionService.create_session(
			builders,
			expiration=session_expiration,
		)
		L.log(
			asab.LOG_NOTICE,
			"Authentication/login successful.",
			struct_data={
				'cid': credentials_id,
				'sid': str(session.SessionId),
				'fi': from_info,
			}
		)

		# Add an audit entry
		# TODO: Add the IP address
		await self.AuditService.append(
			AuditCode.LOGIN_SUCCESS,
			{
				'cid': credentials_id,
				'sid': str(session.SessionId),
				'fi': from_info,
			}
		)

		return session
