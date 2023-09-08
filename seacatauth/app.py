import os
import logging
import secrets

import asab
import asab.web
import asab.metrics
import asab.web.rest
import asab.storage
import asab.proactor

from . import middleware

#

L = logging.getLogger(__name__)


#


class SeaCatAuthApplication(asab.Application):

	def __init__(self):
		super().__init__()
		self.Provisioning = self._should_activate_provisioning()
		self._check_encryption_config()

		# Load modules
		self.add_module(asab.web.Module)
		self.add_module(asab.proactor.Module)
		self.add_module(asab.storage.Module)
		self.add_module(asab.metrics.Module)

		# Locate web service
		self.WebService = self.get_service("asab.WebService")

		# Create admin container
		self.WebContainer = asab.web.WebContainer(self.WebService, "web")
		self.WebContainer.WebApp.middlewares.append(asab.web.rest.JsonExceptionMiddleware)
		self.WebContainer.WebApp.middlewares.append(middleware.app_middleware_factory(self))

		# Create public container
		self.PublicWebContainer = asab.web.WebContainer(self.WebService, "web:public")
		self.PublicWebContainer.WebApp.middlewares.append(asab.web.rest.JsonExceptionMiddleware)
		self.PublicWebContainer.WebApp.middlewares.append(middleware.app_middleware_factory(self))

		# Initialize metrics service
		self.add_module(asab.metrics.Module)

		# Api service
		from asab.api import ApiService
		self.ApiService = ApiService(self)
		self.ApiService.initialize_web(self.WebContainer)

		from .audit import AuditService, AuditHandler
		self.AuditService = AuditService(self)
		self.AuditHandler = AuditHandler(self, self.AuditService)

		# Load Resource service
		from .authz import ResourceService, ResourceHandler
		self.ResourceService = ResourceService(self)
		self.ResourceHandler = ResourceHandler(self, self.ResourceService)

		# Load RBAC service
		from .authz import RBACService, RBACHandler
		self.RBACService = RBACService(self)
		self.RBACHandler = RBACHandler(self, self.RBACService)

		from .communication import CommunicationService
		self.CommunicationService = CommunicationService(self)

		# Init Name Proposer service
		from .nameproposer import NameProposerService
		self.NameProposerService = NameProposerService(self)

		# Init Session service
		from .session import SessionService, SessionHandler
		self.SessionService = SessionService(self)
		self.SessionWebHandler = SessionHandler(self, self.SessionService)

		# Init Tenant service
		from .tenant import TenantService, TenantHandler
		self.TenantService = TenantService(self)
		self.TenantHandler = TenantHandler(self, self.TenantService)

		# Init Credentials services
		from .credentials import CredentialsService, CredentialsHandler
		self.CredentialService = CredentialsService(self, tenant_service=self.TenantService)
		self.CredentialWebHandler = CredentialsHandler(self, self.CredentialService)

		from .credentials.change_password import ChangePasswordService, ChangePasswordHandler
		self.ChangePasswordService = ChangePasswordService(self, self.CredentialService)
		self.ChangePasswordHandler = ChangePasswordHandler(self, self.ChangePasswordService)

		from .credentials.registration import RegistrationService, RegistrationHandler
		self.RegistrationService = RegistrationService(self, self.CredentialService)
		if self.RegistrationService.Enabled:
			self.RegistrationHandler = RegistrationHandler(self, self.RegistrationService, self.CredentialService)

		# Load Role service
		# depends on: ResourceService, TenantService, CredentialService
		from .authz import RoleService, RoleHandler, RolesHandler
		self.RoleService = RoleService(self)
		self.RoleHandler = RoleHandler(self, self.RoleService)
		self.RoleHandler = RolesHandler(self, self.RoleService)

		# Load Cookie service
		# depends on: SessionService, CredentialsService
		from .cookie import CookieService, CookieHandler
		self.CookieService = CookieService(self)
		self.CookieHandler = CookieHandler(self, self.CookieService, self.SessionService, self.CredentialService)

		# Initialize Batman if requested so in config
		self.BatmanService = None
		self.BatmanHandler = None
		for section in asab.Config.sections():
			if section.startswith("batman"):
				from .batman import BatmanService, BatmanHandler
				self.BatmanService = BatmanService(self)
				self.BatmanHandler = BatmanHandler(self, self.BatmanService)
				break

		from .authn.webauthn import WebAuthnService, WebAuthnHandler
		self.WebAuthnService = WebAuthnService(self)
		self.WebAuthnHandler = WebAuthnHandler(self, self.WebAuthnService)

		# Init Login service
		# depends on: ResourceService, TenantService, RoleService, CredentialService, BatmanService
		from .authn import AuthenticationService, AuthenticationHandler, M2MIntrospectHandler
		self.AuthenticationService = AuthenticationService(self)
		self.AuthenticationHandler = AuthenticationHandler(self, self.AuthenticationService)
		self.M2MIntrospectHandler = M2MIntrospectHandler(
			self,
			self.AuthenticationService,
			self.SessionService,
			self.CredentialService,
			self.RBACService
		)

		# Client service
		from .client import ClientService, ClientHandler
		self.ClientService = ClientService(self)
		self.ClientHandler = ClientHandler(self, self.ClientService)

		# Load OpenID Connect module
		# depends on: CookieService, SessionService, AuthenticationService,
		#   CredentialsService, TenantService, RoleService, ClientService
		from .openidconnect import OpenIdConnectModule
		self.add_module(OpenIdConnectModule)

		# Depends on: OpenIDService
		self.WebContainer.WebApp.middlewares.append(middleware.private_auth_middleware_factory(self))
		self.PublicWebContainer.WebApp.middlewares.append(middleware.public_auth_middleware_factory(self))

		from .otp import OTPHandler, OTPService
		self.OTPService = OTPService(self)
		self.OTPHandler = OTPHandler(self, self.OTPService)

		from .external_login import ExternalLoginService, ExternalLoginHandler
		self.ExternalLoginService = ExternalLoginService(self)
		self.ExternalLoginHandler = ExternalLoginHandler(self, self.ExternalLoginService)

		from .feature import FeatureService, FeatureHandler
		self.FeatureService = FeatureService(self)
		self.FeatureHandler = FeatureHandler(self, self.FeatureService)

		# Provisioning service
		# depends on: RoleService, CredentialService
		if self.Provisioning:
			from .provisioning import ProvisioningService
			self.ProvisioningService = ProvisioningService(self)

	def _check_encryption_config(self):
		if len(asab.Config.get("asab:storage", "aes_key", fallback="")) == 0:
			raise ValueError(
				"No encryption 'aes_key' specified in [asab:storage] config section. Please supply an encryption key. "
				"You may use the following randomly generated example: "
				"""
				```
				[asab:storage]
				aes_key={}
				```
				""".replace("\t", "").format(secrets.token_urlsafe(16))
			)

	def _should_activate_provisioning(self):
		# Activate via argparse flag
		if hasattr(self.Args, "provisioning") and self.Args.provisioning:
			return True

		# Activate via env variable
		provisioning_env_name = asab.Config.get("seacatauth:provisioning", "env_variable_name")
		if provisioning_env_name is not None \
			and os.getenv(provisioning_env_name, "false").lower() in ["true", "yes", "1"]:
			return True

		return False

	def create_argument_parser(
		self,
		prog=None,
		usage=None,
		description=None,
		epilog=None,
		prefix_chars='-',
		fromfile_prefix_chars=None,
		argument_default=None,
		conflict_handler='error',
		add_help=True
	):
		parser = super().create_argument_parser(
			prog=prog,
			usage=usage,
			description=description,
			epilog=epilog,
			prefix_chars=prefix_chars,
			fromfile_prefix_chars=fromfile_prefix_chars,
			argument_default=argument_default,
			conflict_handler=conflict_handler,
			add_help=add_help
		)
		parser.add_argument("--provisioning", help="run SeaCat Auth in provisioning mode", action="store_true")
		return parser
