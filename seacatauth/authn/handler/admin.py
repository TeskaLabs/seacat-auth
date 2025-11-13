import logging
import asab
import asab.web.rest
import asab.web.auth
import asab.web.tenant
import asab.exceptions
import asab.contextvars

from ... import exceptions


L = logging.getLogger(__name__)


class AuthenticationAdminHandler(object):
	"""
	Login and authentication

	---
	tags: ["Login and authentication"]
	"""

	def __init__(self, app, authn_svc):
		self.App = app
		self.AuthenticationService = authn_svc
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/admin/credentials/{credentials_id}/authn", self.list_authn_methods)


	@asab.web.tenant.allow_no_tenant
	async def list_authn_methods(self, request):
		"""
		"""
		ext_credentials_svc = self.App.get_service("seacatauth.ExternalCredentialsService")
		webauthn_svc = self.App.get_service("seacatauth.WebAuthnService")
		otp_svc = self.App.get_service("seacatauth.OTPService")

		credentials_id = request.match_info["credentials_id"]
		try:
			credentials = await self.CredentialsService.get(credentials_id, include=["__password"])
		except exceptions.CredentialsNotFoundError as e:
			return e.json_response(request)

		methods = []

		# Add password
		if credentials.get("__password") is not None:
			methods.append({
				"_id": self._make_authn_method_id("password", credentials),
				"type": "password",
				"label": "Password",
			})

		# Add OTP
		has_activated_totp = await otp_svc.has_activated_totp(credentials_id)
		if has_activated_totp:
			methods.append({
				"_id": self._make_authn_method_id("totp", credentials),
				"type": "totp",
				"label": "TOTP",
			})

		# Add Webauthn credentials
		webauthn_credentials = await webauthn_svc.list_webauthn_credentials(
			credentials_id, rest_normalize=True)
		for cred in webauthn_credentials:
			methods.append({
				"_id": self._make_authn_method_id("webauthn", cred),
				"_c": cred.get("_c"),
				"_m": cred.get("_m"),
				"_v": cred.get("_v"),
				"type": "webauthn",
				"label": cred.get("label") or cred.get("name"),
				"last_login": cred.get("last_login"),
			})

		# Add external login accounts
		ext_accounts = await ext_credentials_svc.list_ext_credentials(credentials_id)
		for account in ext_accounts:
			methods.append({
				"_id": self._make_authn_method_id("external", account),
				"type": "external",
				"provider": account.get("type"),
				"label": "{} - {}".format(account.get("provider_label"), account.get("label")),
				"email": account.get("email"),
				"username": account.get("username"),
				"sub": account.get("sub"),
			})

		return asab.web.rest.json_response(request, {
			"data": methods,
			"count": len(methods),
		})


	def _make_authn_method_id(self, method_type: str, method_data: dict):
		match method_type:
			case "password":
				return "password:{}".format(method_data.get("_id"))
			case "totp":
				return "totp:{}".format(method_data.get("_id"))
			case "webauthn":
				return "webauthn:{}".format(method_data.get("id"))
			case "external":
				return "external:{}".format(method_data.get("_id"))
			case _:
				raise ValueError("Unknown authentication method type '{}'".format(method_type))


	def _parse_authn_method_id(self, authn_method_id: str):
		parts = authn_method_id.split(":", 1)
		if len(parts) != 2:
			raise ValueError("Invalid authentication method ID '{}'".format(authn_method_id))
		return parts[0], parts[1]


	def get_authn_method_provider(self, authn_method_type: str):
		match authn_method_type:
			case "password":
				return self.App.get_service("seacatauth.CredentialsService")
			case "totp":
				return self.App.get_service("seacatauth.OTPService")
			case "webauthn":
				return self.App.get_service("seacatauth.WebAuthnService")
			case "external":
				return self.App.get_service("seacatauth.ExternalCredentialsService")
			case _:
				raise ValueError("Unknown authentication method type '{}'".format(authn_method_type))
