import logging
import secrets
import aiohttp
import typing
import datetime
import asab
import asab.web.rest

from ... import exceptions, AuditLogger, generic
from ...last_activity import EventCode
from ...models import Session
from ...events import EventTypes
from ...api import local_authz
from .utils import AuthOperation
from .providers import ExternalAuthProviderABC, create_provider
from ..exceptions import (
	LoginWithExternalAccountError,
	SignupWithExternalAccountError,
	PairingExternalAccountError,
	ExternalAccountNotFoundError,
	ExternalLoginError,
)
from ...models.const import ResourceId


L = logging.getLogger(__name__)


class ExternalAuthenticationService(asab.Service):
	"""
	Service to handle authentication using external identity providers (e.g., Google, Facebook, SAML).
	Manages the authentication flow, including redirecting users to the provider, handling callbacks,
	and creating or linking user accounts based on the external identity information.
	"""

	ExternalLoginStateCollection = "els"

	def __init__(self, app, service_name="seacatauth.ExternalAuthenticationService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.SessionService = None
		self.AuthenticationService = None
		self.LastActivityService = None
		self.CookieService = None
		self.ExternalCredentialsService = None

		self.StateLength = asab.Config.getint("seacatauth:external_login", "state_length")
		self.StateExpiration = datetime.timedelta(seconds=asab.Config.getseconds(
			"seacatauth:external_login", "state_expiration"))

		self.CallbackEndpointPath = "/public/ext-login/callback"
		self.CallbackUrlTemplate = "{}{}".format(
			app.PublicSeacatAuthApiUrl,
			self.CallbackEndpointPath.lstrip("/")
		)

		self.DefaultRedirectUri = asab.Config.get("seacatauth:external_login", "default_redirect_uri")
		if not self.DefaultRedirectUri:
			self.DefaultRedirectUri = "{}#/".format(app.AuthWebUiUrl)  # "My account" page

		app.PubSub.subscribe("Application.housekeeping!", self._delete_expired_states)

		self.Providers: typing.Dict[str, ExternalAuthProviderABC] = {}
		self._prepare_providers()


	def _prepare_providers(self):
		for section in asab.Config.sections():
			provider = create_provider(self, section)
			if provider is not None:
				self.Providers[provider.Type] = provider


	async def initialize(self, app):
		self.SessionService = app.get_service("seacatauth.SessionService")
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")
		self.LastActivityService = app.get_service("seacatauth.LastActivityService")
		self.CookieService = app.get_service("seacatauth.CookieService")
		self.ExternalCredentialsService = app.get_service("seacatauth.ExternalCredentialsService")

		for provider in self.Providers.values():
			await provider.initialize(app)


	def get_provider(self, provider_type: str) -> ExternalAuthProviderABC:
		"""
		Get an external identity provider by its type.

		Args:
			provider_type: The type of the external identity provider (e.g., "google", "facebook").

		Returns:
			The external identity provider instance.
		"""
		return self.Providers[provider_type]


	def can_sign_up_new_credentials(self, provider_type: str):
		"""
		Check if new credentials from the given external identity provider can be registered.
		"""
		provider = self.get_provider(provider_type)
		return (
			self.ExternalCredentialsService.RegistrationWebhookUri is not None
			or self.ExternalCredentialsService.RegistrationService.SelfRegistrationEnabled
			or provider.trust_all_credentials()
		)


	async def initialize_login_with_ext_provider(
		self,
		provider_type: str,
		redirect_uri: typing.Optional[str]
	) -> str:
		response = await self._prepare_external_auth_request(
			provider_type, operation=AuthOperation.LogIn, redirect_uri=redirect_uri)
		L.log(asab.LOG_NOTICE, "Initialized login with external account.", struct_data={
			"provider": provider_type})
		return response


	async def initialize_signup_with_ext_provider(
		self,
		provider_type: str,
		redirect_uri: typing.Optional[str]
	) -> str:
		if not self._can_sign_up_new_credentials(provider_type):
			L.error("Signup with external account is not enabled.")
			raise exceptions.RegistrationNotOpenError()
		response = await self._prepare_external_auth_request(
			provider_type, operation=AuthOperation.SignUp, redirect_uri=redirect_uri)
		L.log(asab.LOG_NOTICE, "Initialized sign-up with external account.", struct_data={
			"provider": provider_type})
		return response



	async def initialize_pairing_with_ext_provider(
		self,
		provider_type: str,
		redirect_uri: typing.Optional[str]
	) -> str:
		response = await self._prepare_external_auth_request(
			provider_type, operation=AuthOperation.PairAccount, redirect_uri=redirect_uri)
		L.log(asab.LOG_NOTICE, "Initialized pairing external account.", struct_data={
			"provider": provider_type})
		return response


	async def _prepare_external_auth_request(
		self,
		provider_type: str,
		operation: AuthOperation,
		redirect_uri: typing.Optional[str],
	) -> aiohttp.web.Response:
		provider = self.get_provider(provider_type)
		state_id = operation.value + secrets.token_urlsafe(self.StateLength - 1)
		state = {
			"state_id": state_id,
			"provider": provider_type,
			"operation": operation,
			"redirect_uri": redirect_uri,
		}
		state, response = await provider.prepare_auth_request(state=state)
		await self._create_state(**state)
		return response


	async def process_external_auth_callback(
		self,
		request: aiohttp.web.Request,
		payload: dict,
	) -> typing.Tuple[AuthOperation, typing.Any, str]:
		"""
		Process the authorization response from the external account provider.
		Determine the operation (login, signup, pairing) and call the appropriate handler.

		Args:
			request: The incoming HTTP request.
			payload: The payload containing authorization response data.

		Returns:
			A tuple containing the executed operation code (AuthOperation), the new or updated SSO session object, and
			the redirect URI.
		"""
		state_id = _get_auth_callback_state_id(payload)
		state = await self._get_state(state_id)

		provider_type = state["provider"]
		provider = self.get_provider(provider_type)
		user_info = await provider.process_auth_callback(request, payload, state)
		if "sub" not in user_info:
			L.error("User info does not contain the mandatory 'sub' claim.", struct_data={
				"provider": provider_type, "user_info": user_info})
			raise ExternalLoginError("User info does not contain the mandatory 'sub' claim.")

		match operation_code := state["_id"][0]:
			case AuthOperation.LogIn:
				operation_code, sso_session = await self._finalize_login_with_ext_provider(
					request, payload, user_info, state)
			case AuthOperation.SignUp:
				operation_code, sso_session = await self._finalize_signup_with_ext_provider(
					request, payload, user_info, state)
			case AuthOperation.PairAccount:
				operation_code, sso_session = await self._finalize_pairing_with_ext_provider(
					request, payload, user_info, state)
			case _:
				raise ValueError("Unknown operation code {!r}".format(operation_code))

		redirect_uri = self._get_final_redirect_uri(state)

		await self._delete_state(state["_id"])

		return operation_code, sso_session, redirect_uri


	async def _finalize_login_with_ext_provider(
		self,
		request: aiohttp.web.Request,
		payload: dict,
		user_info: dict,
		state: dict,
	) -> typing.Tuple[AuthOperation, typing.Optional[Session]]:
		"""
		Log the user in using their external account.

		Args:
			request: The incoming HTTP request.
			payload: The payload containing authorization response data.
			state: The state object retrieved from storage.
			user_info: The user information obtained from the external login provider.

		Returns:
			A tuple containing the operation type (AuthOperation) that was executed and the new SSO session object.
		"""
		# Find the external account and its associated Seacat credentials ID
		provider_type = state["provider"]
		try:
			with local_authz(self.Name, resources={ResourceId.CREDENTIALS_ACCESS}):
				account = await self.ExternalCredentialsService.get_ext_credentials(
					provider_type, subject_id=user_info["sub"])
			credentials_id = account["cid"]
		except ExternalAccountNotFoundError as e:
			L.log(asab.LOG_NOTICE, "External account not found.", struct_data={
				"type": e.ProviderType, "sub": e.SubjectId})
			if not self._can_sign_up_new_credentials(provider_type):
				raise LoginWithExternalAccountError(
					"Logged in with unknown external account; sign-up not allowed.",
					provider_type=e.ProviderType,
					subject_id=e.SubjectId,
				) from e

			# Create Seacat credentials
			credentials_id = await self._create_new_seacat_auth_credentials(
				provider_type, user_info, payload)
			# Pair the external account with the created credentials
			await self.ExternalLoginAccountStorage.create(credentials_id, provider_type, user_info)

			# Log the user in
			with local_authz(self.Name, resources={ResourceId.CREDENTIALS_ACCESS}):
				new_sso_session = await self._login(
					credentials_id=credentials_id,
					provider_type=provider_type,
					current_sso_session=None,
				)

			return AuthOperation.SignUp, new_sso_session

		# Get current SSO session (if any) to determine if we are re-logging in or logging in anew
		cookie_service = self.App.get_service("seacatauth.CookieService")
		try:
			current_sso_session = await cookie_service.get_session_by_request_cookie(request)
		except (exceptions.NoCookieError, exceptions.SessionNotFoundError):
			current_sso_session = None

		# Log the user in
		if current_sso_session and current_sso_session.Credentials.Id != credentials_id:
			# The external account belongs to someone else than who is logged in
			# Ignore the current SSO session and log in, its cookie will be overwritten
			current_sso_session = None

		with local_authz(self.Name, resources={ResourceId.CREDENTIALS_ACCESS}):
			new_sso_session = await self._login(
				credentials_id=credentials_id,
				provider_type=provider_type,
				current_sso_session=current_sso_session,
			)

		return AuthOperation.LogIn, new_sso_session


	async def _finalize_signup_with_ext_provider(
		self,
		request: aiohttp.web.Request,
		payload: dict,
		user_info: dict,
		state: dict,
	) -> typing.Tuple[AuthOperation, typing.Any]:
		"""
		Sign up a new user using their external account.

		Args:
			request: The incoming HTTP request.
			payload: The payload containing authorization response data.
			state: The state object retrieved from storage.
			user_info: The user information obtained from the external login provider.

		Returns:
			A tuple containing the operation type (AuthOperation) that was executed and the new SSO session object.
		"""
		# Find the external account and its associated Seacat credentials ID
		provider_type = state["provider"]

		# Verify that the external account is not registered already
		try:
			with local_authz(self.Name, resources={ResourceId.CREDENTIALS_ACCESS}):
				await self.ExternalCredentialsService.get_ext_credentials(
					provider_type, subject_id=user_info["sub"])
			L.log(asab.LOG_NOTICE, "Cannot sign up with external account: Account already paired.", struct_data={
				"provider": provider_type, "sub": user_info.get("sub")})
			raise SignupWithExternalAccountError(
				"External account already signed up.",
				provider_type=provider_type,
				subject_id=user_info["sub"],
			)
		except ExternalAccountNotFoundError:
			# Unknown account can be used for signup
			pass

		if not self.can_sign_up_new_credentials(provider_type):
			L.error("Sign-up with external account not enabled.")
			raise SignupWithExternalAccountError(
				"Sign-up with external account not enabled.",
				provider_type=provider_type,
				subject_id=user_info["sub"],
			)

		# Create credentials and pair external account in one step
		credentials_id = await self.ExternalCredentialsService.sign_up_ext_credentials(
			provider_type, user_info, payload)

		# Log the user in
		sso_session = await self._login(
			credentials_id=credentials_id,
			provider_type=provider_type,
			current_sso_session=None,
		)

		return AuthOperation.SignUp, sso_session


	async def _finalize_pairing_with_ext_provider(
		self,
		request: aiohttp.web.Request,
		payload: dict,
		user_info: dict,
		state: dict,
	) -> typing.Tuple[AuthOperation, typing.Any]:
		"""
		Pair external account with the current user's credentials.

		Args:
			request: The incoming HTTP request.
			payload: The payload containing authorization response data.
			state: The state object retrieved from storage.
			user_info: The user information obtained from the external login provider.

		Returns:
			A tuple containing the operation type (AuthOperation) that was executed and the new SSO session object.
		"""
		provider_type = state["provider"]

		# Get current SSO session (if any) to determine if we are re-logging in or logging in anew
		cookie_service = self.App.get_service("seacatauth.CookieService")
		try:
			current_sso_session = await cookie_service.get_session_by_request_cookie(request)
		except (exceptions.NoCookieError, exceptions.SessionNotFoundError):
			L.error("Cannot finalize pairing external account: No active SSO session.", struct_data={
				"provider": provider_type,
				"sub": user_info.get("sub"),
				"state": state["_id"],
			})
			raise exceptions.AccessDeniedError("Authentication required")

		if current_sso_session.is_anonymous():
			L.error("Cannot finalize pairing external account: Anonymous SSO session.", struct_data={
				"provider": provider_type,
				"sub": user_info.get("sub"),
				"state": state["_id"],
			})
			raise exceptions.AccessDeniedError("Authentication required")

		credentials_id = current_sso_session.Credentials.Id

		# TODO: Require fresh authentication and user confirmation
		try:
			with local_authz(self.Name, resources={ResourceId.CREDENTIALS_EDIT}):
				await self.ExternalCredentialsService.create_ext_credentials(
					credentials_id, provider_type, user_info)
		except asab.exceptions.Conflict as e:
			L.error(
				"Cannot finalize pairing external account: Already paired to different credentials.",
				struct_data={
					"cid": credentials_id,
					"provider": provider_type,
					"sub": user_info.get("sub"),
				}
			)
			raise PairingExternalAccountError(
				"External account already paired.",
				subject_id=user_info.get("sub"),
				credentials_id=credentials_id,
				provider_type=provider_type,
			) from e

		return AuthOperation.PairAccount, None


	async def _login(
		self,
		credentials_id: str,
		provider_type: str,
		current_sso_session: typing.Optional[Session] = None,
	):
		from_ip = generic.get_request_access_ips(asab.contextvars.Request.get())

		# Create ad-hoc login descriptor
		login_descriptor = {
			"id": "!external",
			"factors": [{"type": "ext:{}".format(provider_type)}]
		}

		session_builders = await self.SessionService.build_sso_root_session(
			credentials_id=credentials_id,
			login_descriptor=login_descriptor,
		)
		if current_sso_session and not current_sso_session.is_anonymous():
			# Update existing SSO root session (re-login)
			assert current_sso_session.Session.Type == "root"
			assert current_sso_session.Credentials.Id == credentials_id
			new_sso_session = await self.SessionService.update_session(
				current_sso_session.SessionId,
				session_builders=session_builders
			)
		else:
			# Create a new root session
			new_sso_session = await self.SessionService.create_session(
				session_type="root",
				session_builders=session_builders,
			)

		AuditLogger.log(asab.LOG_NOTICE, "Authentication successful", struct_data={
			"cid": credentials_id,
			"lsid": "<external-login>",
			"sid": str(new_sso_session.Session.Id),
			"from_ip": from_ip,
			"authn_by": login_descriptor,
		})
		await self.LastActivityService.update_last_activity(
			EventCode.LOGIN_SUCCESS, credentials_id, from_ip=from_ip, authn_by=login_descriptor)

		return new_sso_session


	def _get_final_redirect_uri(self, state: dict):
		if "redirect_uri" in state and state["redirect_uri"]:
			return state["redirect_uri"]
		# No redirect_uri was specified; redirect to default URL
		return self.DefaultRedirectUri


	async def _create_state(
		self,
		state_id: str,
		provider: str,
		operation: AuthOperation,
		redirect_uri: typing.Optional[str] = None,
		nonce: typing.Optional[str] = None,
	):
		upsertor = self.StorageService.upsertor(self.ExternalLoginStateCollection, obj_id=state_id)
		upsertor.set("provider", provider)
		upsertor.set("operation", operation.value)
		if redirect_uri:
			upsertor.set("redirect_uri", redirect_uri)
		if nonce:
			upsertor.set("nonce", nonce)
		state_id = await upsertor.execute(event_type=EventTypes.EXTERNAL_LOGIN_STATE_CREATED)
		return state_id


	async def _get_state(self, state_id):
		state = await self.StorageService.get(self.ExternalLoginStateCollection, state_id)
		if state["_c"] < datetime.datetime.now(datetime.timezone.utc) - self.StateExpiration:
			raise KeyError(state_id)
		state["operation"] = AuthOperation.deserialize(state["operation"])
		return state


	async def _update_state(self, state_id):
		raise NotImplementedError()


	async def _delete_state(self, state_id):
		return await self.StorageService.delete(self.ExternalLoginStateCollection, state_id)


	async def _delete_expired_states(self, *args, **kwargs):
		collection = self.StorageService.Database[self.ExternalLoginStateCollection]
		query = {"_c": {"$lt": datetime.datetime.now(datetime.timezone.utc) - self.StateExpiration}}
		result = await collection.delete_many(query)
		if result.deleted_count > 0:
			L.info("Expired external login states deleted.", struct_data={
				"count": result.deleted_count
			})


def _get_auth_callback_state_id(payload: dict) -> str:
	"""
	Extract the state ID from the authorization response payload.
	Raise ValueError if the state ID is missing or if both "state" and "RelayState" are present.
	Supports both OAuth2 ("state") and SAML ("RelayState") parameters.

	Args:
		payload: The payload containing authorization response data.
	"""
	if "state" in payload and "RelayState" in payload:
		L.error(
			"Authorization response payload cannot contain both 'state' and 'RelayState' at once.",
			struct_data={"payload": payload}
		)
		raise ValueError("Authorization response payload cannot contain both 'state' and 'RelayState' at once.")

	if "state" in payload:
		# OAuth2 providers
		assert "RelayState" not in payload
		state_id = payload["state"]
	elif "RelayState" in payload:
		# SAML providers
		assert "state" not in payload
		state_id = payload["RelayState"]
	else:
		L.error("No state in authorization response payload.", struct_data={"payload": payload})
		raise ValueError("No state in authorization response payload")

	return state_id
