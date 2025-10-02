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

		self.LoginUri = "{}#/login".format(app.AuthWebUiUrl)
		self.DefaultRedirectUri = asab.Config.get("seacatauth:external_login", "default_redirect_uri")
		if not self.DefaultRedirectUri:
			self.DefaultRedirectUri = app.PublicUrl

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
		return (
			self.ExternalCredentialsService.RegistrationWebhookUri
			or self.ExternalCredentialsService.RegistrationService.SelfRegistrationEnabled
		)


	async def initialize_login_with_ext_provider(
		self,
		provider_type: str,
		redirect_uri: typing.Optional[str]
	) -> aiohttp.web.Response:
		response = await self._prepare_external_auth_request(
			provider_type, operation=AuthOperation.LogIn, redirect_uri=redirect_uri)
		L.log(asab.LOG_NOTICE, "Initialized login with external account.", struct_data={
			"provider": provider_type})
		return response


	async def initialize_signup_with_ext_provider(
		self,
		provider_type: str,
		redirect_uri: typing.Optional[str]
	) -> aiohttp.web.Response:
		if not self.can_sign_up_new_credentials(provider_type):
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
	) -> aiohttp.web.Response:
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
	) -> aiohttp.web.Response:
		"""
		Process the authorization response from the external account provider.
		Determine the operation (login, signup, pairing) and call the appropriate handler.

		Args:
			request: The incoming HTTP request.
			payload: The payload containing authorization response data.

		Returns:
			Redirect response to the final destination after processing the external authentication.
		"""
		state_id = _get_auth_callback_state_id(payload)
		state = await self._pop_state(state_id)

		match operation_code := state["operation"]:
			case AuthOperation.LogIn:
				return await self._finalize_login_with_ext_provider(
					request, payload, state)
			case AuthOperation.SignUp:
				return await self._finalize_signup_with_ext_provider(
					request, payload, state)
			case AuthOperation.PairAccount:
				return await self._finalize_pairing_with_ext_provider(
					request, payload, state)
			case _:
				raise ValueError("Unknown operation code {!r}".format(operation_code))


	async def _finalize_login_with_ext_provider(
		self,
		request: aiohttp.web.Request,
		payload: dict,
		state: dict,
	) -> aiohttp.web.Response:
		"""
		Log the user in using their external account.

		Args:
			request: The incoming HTTP request.
			payload: The payload containing authorization response data.
			state: The state object retrieved from storage.

		Returns:
			Redirect response to the final destination after processing the external authentication.
		"""
		provider_type = state["provider"]
		provider = self.get_provider(provider_type)

		try:
			user_info = await provider.process_auth_callback(request, payload, state)
		except exceptions.AccessDeniedError as e:
			L.log(asab.LOG_NOTICE, "External authentication failed: Access denied.", struct_data={
				"provider": provider_type,
				"state": state["_id"],
				"error": str(e),
			})
			return self._error_redirect_response(
				self.LoginUri,
				result="login_failed",
				delete_sso_cookie=True,
				redirect_uri=self._get_final_redirect_uri(state),
				ext_login_error="access_denied",
			)
		except ExternalLoginError as e:
			L.log(asab.LOG_NOTICE, "External authentication failed.", struct_data={
				"provider": provider_type,
				"state": state["_id"],
				"error": str(e),
			})
			return self._error_redirect_response(
				self.LoginUri,
				result="login_failed",
				delete_sso_cookie=True,
				redirect_uri=self._get_final_redirect_uri(state)
			)

		# Find the external account and its associated Seacat credentials ID
		try:
			with local_authz(self.Name, resources={ResourceId.CREDENTIALS_ACCESS}):
				account = await self.ExternalCredentialsService.get_ext_credentials(
					provider_type, subject_id=user_info["sub"])
			credentials_id = account["cid"]
		except ExternalAccountNotFoundError as e:
			L.log(asab.LOG_NOTICE, "External account not found.", struct_data={
				"type": e.ProviderType, "sub": e.SubjectId})
			if not self.can_sign_up_new_credentials(provider_type):
				# Redirect to login page with error message, keep the original redirect uri in the query
				return self._error_redirect_response(
					self.LoginUri,
					result="login_failed",
					delete_sso_cookie=True,
					ext_login_error="not_found",
					redirect_uri=self._get_final_redirect_uri(state)
				)

			# Create credentials and pair external account
			try:
				credentials_id = await self.ExternalCredentialsService.sign_up_ext_credentials(
					provider_type, user_info, payload)
			except exceptions.CredentialsRegistrationError as e:
				L.error("Sign-up with external account failed: {}".format(e))
				return self._error_redirect_response(
					self.LoginUri,
					result="login_failed",
					delete_sso_cookie=True,
					redirect_uri=self._get_final_redirect_uri(state)
				)

			# Log the user in
			with local_authz(self.Name, resources={ResourceId.CREDENTIALS_ACCESS}):
				new_sso_session = await self._login(
					credentials_id=credentials_id,
					provider_type=provider_type,
					current_sso_session=None,
				)

			return self._success_redirect_response(
				self._get_final_redirect_uri(state), "signup_success", sso_session=new_sso_session)

		# Get current SSO session (if any) to determine if we are re-logging in or logging in anew
		try:
			current_sso_session = await self.CookieService.get_session_by_request_cookie(request)
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

		return self._success_redirect_response(
			self._get_final_redirect_uri(state), "login_success", sso_session=new_sso_session)


	async def _finalize_signup_with_ext_provider(
		self,
		request: aiohttp.web.Request,
		payload: dict,
		state: dict,
	) -> aiohttp.web.Response:
		"""
		Sign up a new user using their external account.

		Args:
			request: The incoming HTTP request.
			payload: The payload containing authorization response data.
			state: The state object retrieved from storage.

		Returns:
			Redirect response to the final destination after processing the external authentication.
		"""
		provider_type = state["provider"]
		provider = self.get_provider(provider_type)

		try:
			user_info = await provider.process_auth_callback(request, payload, state)
		except exceptions.AccessDeniedError as e:
			L.log(asab.LOG_NOTICE, "External authentication failed: Access denied.", struct_data={
				"provider": provider_type,
				"state": state["_id"],
				"error": str(e),
			})
			return self._error_redirect_response(
				self.LoginUri,
				result="signup_failed",
				delete_sso_cookie=True,
				redirect_uri=self._get_final_redirect_uri(state),
				ext_login_error="access_denied",
			)
		except ExternalLoginError as e:
			L.log(asab.LOG_NOTICE, "External authentication failed.", struct_data={
				"provider": provider_type,
				"state": state["_id"],
				"error": str(e),
			})
			return self._error_redirect_response(
				self.LoginUri,
				result="signup_failed",
				delete_sso_cookie=True,
				redirect_uri=self._get_final_redirect_uri(state)
			)

		if not self.can_sign_up_new_credentials(provider_type):
			L.error("Sign-up with external account not enabled.")
			return self._error_redirect_response(
				self.LoginUri,
				result="signup_failed",
				delete_sso_cookie=True,
				ext_login_error="registration_disabled",
				redirect_uri=self._get_final_redirect_uri(state)
			)

		# Verify that the external account is not registered already
		try:
			with local_authz(self.Name, resources={ResourceId.CREDENTIALS_ACCESS}):
				await self.ExternalCredentialsService.get_ext_credentials(
					provider_type, subject_id=user_info["sub"])
			L.log(asab.LOG_NOTICE, "Cannot sign up with external account: Account already paired.", struct_data={
				"provider": provider_type, "sub": user_info.get("sub")})
			return self._error_redirect_response(
				self.LoginUri,
				result="signup_failed",
				delete_sso_cookie=True,
				ext_login_error="already_exists",
				redirect_uri=self._get_final_redirect_uri(state)
			)

		except ExternalAccountNotFoundError:
			# Unknown account can be used for signup
			pass

		# Create credentials and pair external account in one step
		try:
			credentials_id = await self.ExternalCredentialsService.sign_up_ext_credentials(
				provider_type, user_info, payload)
		except exceptions.CredentialsRegistrationError as e:
			L.error("Sign-up with external account failed: {}".format(e))
			return self._error_redirect_response(
				self.LoginUri,
				result="signup_failed",
				delete_sso_cookie=True,
				redirect_uri=self._get_final_redirect_uri(state)
			)

		# Log the user in
		sso_session = await self._login(
			credentials_id=credentials_id,
			provider_type=provider_type,
			current_sso_session=None,
		)

		return self._success_redirect_response(
			self._get_final_redirect_uri(state), "signup_success", sso_session=sso_session)


	async def _finalize_pairing_with_ext_provider(
		self,
		request: aiohttp.web.Request,
		payload: dict,
		state: dict,
	) -> aiohttp.web.Response:
		"""
		Pair external account with the current user's credentials.

		Args:
			request: The incoming HTTP request.
			payload: The payload containing authorization response data.
			state: The state object retrieved from storage.

		Returns:
			Redirect response to the final destination after processing the external authentication.
		"""
		provider_type = state["provider"]
		provider = self.get_provider(provider_type)

		try:
			user_info = await provider.process_auth_callback(request, payload, state)
		except exceptions.AccessDeniedError as e:
			L.log(asab.LOG_NOTICE, "External authentication failed: Access denied.", struct_data={
				"provider": provider_type,
				"state": state["_id"],
				"error": str(e),
			})
			return self._error_redirect_response(
				self.LoginUri,
				result="pairing_failed",
				redirect_uri=self._get_final_redirect_uri(state),
				ext_login_error="access_denied",
			)
		except ExternalLoginError as e:
			L.log(asab.LOG_NOTICE, "External authentication failed.", struct_data={
				"provider": provider_type,
				"state": state["_id"],
				"error": str(e),
			})
			return self._error_redirect_response(
				self._get_final_redirect_uri(state),
				result="pairing_failed",
			)

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
			return self._error_redirect_response(
				self.LoginUri,
				result="pairing_failed",
				delete_sso_cookie=True,
				ext_login_error="not_authenticated",
				redirect_uri=self._get_final_redirect_uri(state)
			)

		if current_sso_session.is_anonymous():
			L.error("Cannot finalize pairing external account: Anonymous SSO session.", struct_data={
				"provider": provider_type,
				"sub": user_info.get("sub"),
				"state": state["_id"],
			})
			return self._error_redirect_response(
				self.LoginUri,
				result="pairing_failed",
				delete_sso_cookie=True,
				ext_login_error="not_authenticated",
				redirect_uri=self._get_final_redirect_uri(state)
			)

		credentials_id = current_sso_session.Credentials.Id

		# TODO: Require fresh authentication and user confirmation
		try:
			with local_authz(self.Name, resources={ResourceId.CREDENTIALS_EDIT}):
				await self.ExternalCredentialsService.create_ext_credentials(
					credentials_id, provider_type, user_info)
		except asab.exceptions.Conflict:
			L.error(
				"Cannot finalize pairing external account: Record for this account already exists.",
				struct_data={
					"cid": credentials_id,
					"provider": provider_type,
					"sub": user_info.get("sub"),
				}
			)
			return self._error_redirect_response(
				self._get_final_redirect_uri(state),
				result="pairing_failed",
				ext_login_error="already_exists"
			)

		return self._success_redirect_response(
			self._get_final_redirect_uri(state), "pairing_success")


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
		return state.get("redirect_uri") or self.DefaultRedirectUri


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


	async def _pop_state(self, state_id):
		state = await self.StorageService.get(self.ExternalLoginStateCollection, state_id)
		if state["_c"] < datetime.datetime.now(datetime.timezone.utc) - self.StateExpiration:
			raise KeyError(state_id)
		state["operation"] = AuthOperation.deserialize(state["operation"])
		await self.StorageService.delete(self.ExternalLoginStateCollection, state_id)
		return state


	async def _update_state(self, state_id):
		raise NotImplementedError()


	async def _delete_expired_states(self, *args, **kwargs):
		collection = self.StorageService.Database[self.ExternalLoginStateCollection]
		query = {"_c": {"$lt": datetime.datetime.now(datetime.timezone.utc) - self.StateExpiration}}
		result = await collection.delete_many(query)
		if result.deleted_count > 0:
			L.info("Expired external login states deleted.", struct_data={
				"count": result.deleted_count
			})


	def _error_redirect_response(
		self,
		location: str,
		result: str = "error",
		delete_sso_cookie: bool = False,
		**query_params
	) -> aiohttp.web.Response:
		location = _update_url_query(location, ext_login_result=result, **query_params)
		response = aiohttp.web.HTTPNotFound(headers={
			"Location": location,
			"Refresh": "0;url={}".format(location),
		})
		if delete_sso_cookie:
			self.CookieService.delete_session_cookie(response)
		return response


	def _success_redirect_response(
		self,
		location: str,
		result: str = "success",
		sso_session: typing.Optional[Session] = None,
		**query_params
	) -> aiohttp.web.Response:
		location = _update_url_query(location, ext_login_result=result, **query_params)
		response = aiohttp.web.HTTPFound(location)
		if sso_session:
			self.CookieService.set_session_cookie(
				response,
				cookie_value=sso_session.Cookie.Id,
			)
		return response


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


def _update_url_query(url: str, **query_params) -> str:
	"""
	Update the query parameters of a given URL.
	If the URL contains a fragment, the query parameters are added to the fragment instead.
	"""
	if "#" in url:
		base, fragment = url.split("#", 1)
		fragment = generic.update_url_query_params(fragment, **query_params)
		url = "{}#{}".format(base, fragment)
	else:
		url = generic.update_url_query_params(url, **query_params)
	return url
