import os
import logging
import secrets
import jwcrypto.jwk
import urllib.parse
import asab


L = logging.getLogger(__name__)


class SeaCatAuthApplication(asab.Application):

	def __init__(self):
		super().__init__()
		self.Provisioning = self._should_activate_provisioning()
		self._check_encryption_config()
		self.PrivateKey = self._load_private_key()

		self.PublicUrl = None
		self.AuthWebUiApiBaseUrl = None
		self.PublicOpenIdConnectApiUrl = None
		self.AuthWebUiUrl = None
		self._prepare_public_urls()

		# Load modules
		import asab.web
		import asab.web.rest
		self.add_module(asab.web.Module)

		import asab.proactor
		self.add_module(asab.proactor.Module)

		import asab.storage
		self.add_module(asab.storage.Module)

		import asab.metrics
		self.add_module(asab.metrics.Module)

		# Locate web service
		self.WebService = self.get_service("asab.WebService")

		# Create admin container
		self.WebContainer = asab.web.WebContainer(self.WebService, "web")
		self.WebContainer.WebApp.middlewares.append(asab.web.rest.JsonExceptionMiddleware)

		# Create public container
		self.PublicWebContainer = asab.web.WebContainer(self.WebService, "web:public")
		self.PublicWebContainer.WebApp.middlewares.append(asab.web.rest.JsonExceptionMiddleware)

		import asab.web.tenant
		self.AsabTenantService = asab.web.tenant.TenantService(self, strict=False)
		self.AsabTenantService.install(self.WebContainer)
		self.AsabTenantService.install(self.PublicWebContainer)

		import asab.web.auth
		self.AsabAuthService = asab.web.auth.AuthService(self)
		self.AsabAuthService.install(self.WebContainer)
		self.AsabAuthService.install(self.PublicWebContainer)

		# Api service
		import asab.api
		self.ApiService = asab.api.ApiService(self)
		self.ApiService.initialize_web(self.WebContainer)

		if "sentry" in asab.Config:
			import asab.sentry
			self.SentryService = asab.sentry.SentryService(self)

		if "zookeeper" in asab.Config:
			import asab.zookeeper
			self.add_module(asab.zookeeper.Module)
			self.ApiService.initialize_zookeeper()

		from .last_activity import LastActivityService
		self.LastActivityService = LastActivityService(self)

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
		if self.RegistrationService.is_enabled():
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

		from .batman import BatmanService, BatmanHandler
		self.BatmanService = BatmanService(self)
		self.BatmanHandler = BatmanHandler(self, self.BatmanService)

		from .authn.webauthn import WebAuthnService, WebAuthnAccountHandler
		self.WebAuthnService = WebAuthnService(self)
		self.WebAuthnAccountHandler = WebAuthnAccountHandler(self, self.WebAuthnService)

		# Init Login service
		# depends on: ResourceService, TenantService, RoleService, CredentialService, BatmanService
		from .authn import (
			AuthenticationService,
			AuthenticationPublicHandler,
			AuthenticationAccountHandler,
			AuthenticationAdminHandler,
			M2MIntrospectHandler
		)
		self.AuthenticationService = AuthenticationService(self)
		self.AuthenticationPublicHandler = AuthenticationPublicHandler(self, self.AuthenticationService)
		self.AuthenticationAccountHandler = AuthenticationAccountHandler(self, self.AuthenticationService)
		self.AuthenticationAdminHandler = AuthenticationAdminHandler(self, self.AuthenticationService)
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

		from .apikey import ApiKeyService, ApiKeyHandler
		self.ApiKeyService = ApiKeyService(self)
		self.ApiKeyHandler = ApiKeyHandler(self, self.ApiKeyService)

		# Load OpenID Connect module
		# depends on: CookieService, SessionService, AuthenticationService,
		#   CredentialsService, TenantService, RoleService, ClientService
		from .openidconnect import OpenIdConnectModule
		self.add_module(OpenIdConnectModule)

		from .authn.otp import OTPAccountHandler, OTPService
		self.OTPService = OTPService(self)
		self.OTPAccountHandler = OTPAccountHandler(self, self.OTPService)

		from .external_login.authentication import (
			ExternalAuthenticationService,
			ExternalAuthenticationHandler
		)
		self.ExternalAuthenticationService = ExternalAuthenticationService(self)
		self.ExternalLoginPublicHandler = ExternalAuthenticationHandler(self, self.ExternalAuthenticationService)

		from .external_login.credentials import (
			ExternalCredentialsService,
			ExternalLoginAccountHandler,
		)
		self.ExternalCredentialsService = ExternalCredentialsService(self)
		self.ExternalLoginAccountHandler = ExternalLoginAccountHandler(self, self.ExternalCredentialsService)

		from .feature import FeatureService, FeatureHandler
		self.FeatureService = FeatureService(self)
		self.FeatureHandler = FeatureHandler(self, self.FeatureService)

		# Provisioning service
		# depends on: RoleService, CredentialService
		if self.Provisioning:
			from .provisioning import ProvisioningService
			self.ProvisioningService = ProvisioningService(self)


	async def initialize(self):
		from .api import AsabAuthProvider
		auth_provider = AsabAuthProvider(self)
		self.AsabAuthService.Providers.insert(0, auth_provider)  # High priority

		from .api import AsabTenantProvider
		tenant_provider = AsabTenantProvider(self, self.AsabTenantService)
		self.AsabTenantService.Providers.insert(0, tenant_provider)  # High priority


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


	def _load_private_key(self):
		"""
		Load private key from file.
		If it does not exist, generate a new one and write to file.
		"""
		# TODO: Add encryption option
		# TODO: Multiple key support
		if "seacat_auth" in asab.Config:
			asab.LogObsolete.warning(
				"Config section '[seacat_auth]' has been renamed to '[seacatauth]'. "
				"Please update your configuration file.",
				struct_data={"eol": "2024-01-31"})
			asab.Config["seacatauth"].update(asab.Config["seacat_auth"])
		private_key_path = asab.Config.get("seacatauth", "private_key", fallback="")
		if len(private_key_path) == 0 and "private_key" in asab.Config["openidconnect"]:
			asab.LogObsolete.warning(
				"The 'private_key' option has been moved from the 'openidconnect' to the 'seacatauth' section. "
				"Please update your configuration file.",
				struct_data={"eol": "2024-01-31"})
			private_key_path = asab.Config.get("openidconnect", "private_key", fallback="")
		if len(private_key_path) == 0:
			# Use config folder
			private_key_path = os.path.join(
				os.path.dirname(asab.Config.get("general", "config_file")),
				"private-key.pem"
			)
			L.info(
				"Seacat Auth private key file not specified. Defaulting to '{}'.".format(private_key_path)
			)

		if os.path.isfile(private_key_path):
			with open(private_key_path, "rb") as f:
				private_key = jwcrypto.jwk.JWK.from_pem(f.read())
		elif self.Provisioning:
			# Generate a new private key
			L.log(
				asab.LOG_NOTICE,
				"Seacat Auth private key file does not exist. Generating a new one.",
				struct_data={"path": private_key_path}
			)
			private_key = self._generate_private_key(private_key_path)
		else:
			raise FileNotFoundError(
				"Private key file '{}' does not exist. "
				"Run the app in provisioning mode to generate a new private key.".format(private_key_path)
			)

		assert private_key.key_type == "EC"
		assert private_key.key_curve == "P-256"
		return private_key


	def _generate_private_key(self, private_key_path):
		assert not os.path.isfile(private_key_path)

		import cryptography.hazmat.backends
		import cryptography.hazmat.primitives.serialization
		import cryptography.hazmat.primitives.asymmetric.ec
		import cryptography.hazmat.primitives.ciphers.algorithms
		_private_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
			cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
			cryptography.hazmat.backends.default_backend()
		)
		# Serialize into PEM
		private_pem = _private_key.private_bytes(
			encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
			format=cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
			encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption()
		)
		with open(private_key_path, "wb") as f:
			f.write(private_pem)
		L.log(
			asab.LOG_NOTICE,
			"New private key written to '{}'.".format(private_key_path)
		)
		private_key = jwcrypto.jwk.JWK.from_pem(private_pem)
		return private_key


	def create_argument_parser(self, *args, **kwargs):
		parser = super().create_argument_parser(*args, **kwargs)
		parser.add_argument("--provisioning", help="run SeaCat Auth in provisioning mode", action="store_true")
		return parser


	def _prepare_public_urls(self):
		self.PublicUrl = asab.Config.get("general", "public_url")
		if not self.PublicUrl:
			# Check obsoleted option
			public_api_base_url = asab.Config.get("general", "public_api_base_url", fallback=None)
			if public_api_base_url:
				raise ValueError(
					"Config option 'public_api_base_url' in the 'general' section is obsoleted. "
					"Please use the 'PUBLIC_URL' environment variable "
					"or the 'public_url' option in the 'general' config section. "
					"See https://github.com/TeskaLabs/seacat-auth/pull/330 for details."
				)
		if not self.PublicUrl:
			# Try to load config from env variable
			env_public_url = os.getenv("PUBLIC_URL")
			if env_public_url:
				self.PublicUrl = env_public_url
			else:
				self.PublicUrl = "http://localhost"
				L.log(asab.LOG_NOTICE, "No public server URL configured. Falling back to {!r}.".format(self.PublicUrl))

		# Ensure that the URL ends with a slash
		self.PublicUrl = self.PublicUrl.rstrip("/") + "/"
		if not (self.PublicUrl.startswith("https://") or self.PublicUrl.startswith("http://")):
			raise ValueError(
				"The value of 'public_base_url' in 'general' config section does not start "
				"with 'https://' or 'http://' ({!r}). Please supply a full absolute URL.".format(self.PublicUrl))
		if self.PublicUrl.startswith("http://"):
			L.warning(
				"Seacat Auth public interface is running on plain insecure HTTP ({!r}). "
				"This may limit the functionality of certain components.".format(self.PublicUrl))

		# Public base URL of OpenID Connect API
		#   Canonically, this is "${PUBLIC_SERVER_URL}/api/openidconnect/",
		#   yielding for example "https://example.com/api/openidconnect/authorize"
		self.PublicOpenIdConnectApiUrl = asab.Config.get(
			"general", "public_openidconnect_base_url").rstrip("/") + "/"
		if not (
			self.PublicOpenIdConnectApiUrl.startswith("https://")
			or self.PublicOpenIdConnectApiUrl.startswith("http://")
		):
			# Relative URL: Append to PublicUrl
			self.PublicOpenIdConnectApiUrl = urllib.parse.urljoin(self.PublicUrl, self.PublicOpenIdConnectApiUrl)

		# Seacat Auth WebUI URL
		#   Canonically, this is "${PUBLIC_SERVER_URL}/auth/",
		#   yielding for example "https://example.com/auth/#/login"
		self.AuthWebUiUrl = asab.Config.get(
			"general", "auth_webui_base_url").rstrip("/") + "/"
		if not (
			self.AuthWebUiUrl.startswith("https://")
			or self.AuthWebUiUrl.startswith("http://")
		):
			# Relative URL: Append to PublicUrl
			self.AuthWebUiUrl = urllib.parse.urljoin(self.PublicUrl, self.AuthWebUiUrl)

		# URL prefix of Seacat Auth API that is used by the Auth Web UI
		#   Canonically, this is "${PUBLIC_SERVER_URL}/auth/api/seacat-auth/",
		#   yielding for example "https://example.com/auth/api/seacat-auth/public/features"
		back_compat = asab.Config.get(
			"general", "public_seacat_auth_base_url", fallback=None)
		if back_compat is not None:
			asab.LogObsolete.warning(
				"Config option 'public_seacat_auth_base_url' in the 'general' section has been renamed to "
				"'auth_webui_api_base_url'. Please update your configuration file.",
				struct_data={"eol": "2026-01-31"}
			)
		self.AuthWebUiApiBaseUrl = back_compat or asab.Config.get(
			"general", "auth_webui_api_base_url").rstrip("/") + "/"
		if not (
			self.AuthWebUiApiBaseUrl.startswith("https://")
			or self.AuthWebUiApiBaseUrl.startswith("http://")
		):
			# Relative URL: Append to PublicUrl
			self.AuthWebUiApiBaseUrl = urllib.parse.urljoin(self.PublicUrl, self.AuthWebUiApiBaseUrl)

		# Ensure that AuthWebUiApiBaseUrl is a sub-URL of AuthWebUiUrl
		if not self.AuthWebUiApiBaseUrl.startswith(self.AuthWebUiUrl):
			raise ValueError(
				"The 'auth_webui_api_base_url' ({}) is not a sub-URL of the 'auth_webui_base_url' ({}). "
				"Please revise your configuration.".format(
					self.AuthWebUiApiBaseUrl,
					self.AuthWebUiUrl
				)
			)
