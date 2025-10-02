import logging
import aiohttp.web
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.exceptions

from ... import exceptions
from .service import ExternalAuthenticationService



L = logging.getLogger(__name__)


class ExternalAuthenticationHandler(object):
	"""
	External login

	---
	tags: ["Public - External login"]
	"""

	def __init__(self, app, external_authentication_svc: ExternalAuthenticationService):
		self.App = app
		self.ExternalAuthenticationService = external_authentication_svc
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")

		web_app = app.WebContainer.WebApp
		web_app_public = app.PublicWebContainer.WebApp

		web_app.router.add_get("/public/ext-login/{provider_type}/pair", self.pair_external_account)
		web_app.router.add_get("/public/ext-login/{provider_type}/login", self.login_with_external_account)
		web_app.router.add_get("/public/ext-login/{provider_type}/signup", self.sign_up_with_external_account)
		web_app.router.add_get(self.ExternalAuthenticationService.CallbackEndpointPath, self.external_auth_callback)
		web_app.router.add_post(self.ExternalAuthenticationService.CallbackEndpointPath, self.external_auth_callback)

		web_app_public.router.add_get("/public/ext-login/{provider_type}/pair", self.pair_external_account)
		web_app_public.router.add_get("/public/ext-login/{provider_type}/login", self.login_with_external_account)
		web_app_public.router.add_get("/public/ext-login/{provider_type}/signup", self.sign_up_with_external_account)
		web_app_public.router.add_get(self.ExternalAuthenticationService.CallbackEndpointPath, self.external_auth_callback)
		web_app_public.router.add_post(self.ExternalAuthenticationService.CallbackEndpointPath, self.external_auth_callback)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.noauth  # Uses cookie authentication
	async def pair_external_account(self, request):
		"""
		Initialize pairing an external account with the current user's credentials.
		Navigable endpoint, redirects to external login page.

		---
		parameters:
		-	name: redirect_uri
			in: query
			description:
				Where to redirect the user after successful login.
			schema:
				type: string
		"""
		redirect_uri = request.query.get("redirect_uri")
		provider_type = request.match_info["provider_type"]
		return await self.ExternalAuthenticationService.initialize_pairing_with_ext_provider(
			provider_type, redirect_uri)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.noauth  # Uses cookie authentication, expects logged-out user
	async def login_with_external_account(self, request):
		"""
		Initialize login with external account.
		Navigable endpoint, redirects to external login page.
		Can also be used as entrypoint for sign-up:
		When the external account is unknown and sign-up is enabled, Seacat Auth attempts to sign up.

		---
		parameters:
		-	name: redirect_uri
			in: query
			description:
				Where to redirect the user after successful login.
			schema:
				type: string
		"""
		redirect_uri = request.query.get("redirect_uri")
		provider_type = request.match_info["provider_type"]
		return await self.ExternalAuthenticationService.initialize_login_with_ext_provider(
			provider_type, redirect_uri)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.noauth  # Uses cookie authentication, expects logged-out user
	async def sign_up_with_external_account(self, request):
		"""
		Initialize sign up with external account.
		Navigable endpoint, redirects to external login page.

		---
		parameters:
		-	name: redirect_uri
			in: query
			description:
				Where to redirect the user after successful login.
			schema:
				type: string
		"""
		redirect_uri = request.query.get("redirect_uri")
		provider_type = request.match_info["provider_type"]
		try:
			return await self.ExternalAuthenticationService.initialize_signup_with_ext_provider(
				provider_type, redirect_uri)
		except exceptions.RegistrationNotOpenError:
			return aiohttp.web.HTTPNotFound()


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.noauth  # Uses cookie authentication, expects logged-out user
	async def external_auth_callback(self, request):
		"""
		Finalize external account login, sign-up or pairing.
		Navigable endpoint, OAuth2/SAML authorization callback. It must be registered as a redirect URI in app/client
		settings at the external account provider.
		Finishes with redirect to the URL specified at the external auth entrypoint,
		appending `ext_login_result` to the URL query.
		Defined `ext_login_result` values:
			- `login_success`: User logged in successfully with external account.
			- `signup_success`: User was signed up and logged in successfully with external account.
			- `pairing_success`: External account successfully paired with current user's credentials.
			- `login_error`: Logging in with external account failed.
			- `signup_error`: Signing up with external account failed.
			- `pairing_error`: Pairing external account to current user's credentials failed.
		"""
		if request.method == "POST":
			payload = dict(await request.post())
		elif request.method == "GET":
			payload = dict(request.query)
		else:
			raise RuntimeError("Unsupported request method {!r}".format(request.method))

		return await self.ExternalAuthenticationService.process_external_auth_callback(request, payload)
