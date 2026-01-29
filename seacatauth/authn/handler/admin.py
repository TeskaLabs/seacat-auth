import logging
import typing

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
		self.AuthnMethodProviders = {}

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/admin/credentials/{credentials_id}/authn-methods", self.list_authn_methods)
		web_app.router.add_get("/admin/credentials/{credentials_id}/authn-methods/{method_id}", self.get_authn_method)
		web_app.router.add_delete("/admin/credentials/{credentials_id}/authn-methods/{method_id}", self.delete_authn_method)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require_superuser
	async def list_authn_methods(self, request):
		"""
		"""
		credentials_id = request.match_info["credentials_id"]
		try:
			await self.CredentialsService.get(credentials_id, include=["__password"])
		except exceptions.CredentialsNotFoundError as e:
			return e.json_response(request)

		methods = [
			*await self._list_password_methods(credentials_id),
			*await self._list_totp_methods(credentials_id),
			*await self._list_webauthn_methods(credentials_id),
			*await self._list_ext_credential_methods(credentials_id),
		]

		return asab.web.rest.json_response(request, {
			"data": methods,
			"count": len(methods),
		})


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require_superuser
	async def get_authn_method(self, request):
		credentials_id = request.match_info["credentials_id"]
		method_id = request.match_info["method_id"]
		authn_method_type, authn_method_internal_id = self._parse_authn_method_id(method_id)
		match authn_method_type:
			case "password":
				data = await self._get_password_method(credentials_id, authn_method_internal_id)
			case "totp":
				data = await self._get_totp_method(credentials_id, authn_method_internal_id)
			case "webauthn":
				data = await self._get_webauthn_method(credentials_id, authn_method_internal_id)
			case "external":
				data = await self._get_ext_credential_method(credentials_id, authn_method_internal_id)
			case _:
				raise KeyError()

		return asab.web.rest.json_response(request, data)


	@asab.web.tenant.allow_no_tenant
	@asab.web.auth.require_superuser
	async def delete_authn_method(self, request):
		"""
		"""
		credentials_id = request.match_info["credentials_id"]
		method_id = request.match_info["method_id"]
		authn_method_type, authn_method_internal_id = self._parse_authn_method_id(method_id)
		match authn_method_type:
			case "password":
				# Password removal is not allowed for now
				return asab.web.rest.json_response(request, {"result": "NOT-ALLOWED"}, status=405)
			case "totp":
				await self._remove_totp_method(credentials_id, authn_method_internal_id)
			case "webauthn":
				await self._remove_webauthn_method(credentials_id, authn_method_internal_id)
			case "external":
				await self._remove_ext_credential_method(credentials_id, authn_method_internal_id)
			case _:
				raise ValueError("Unknown authentication method type '{}'".format(authn_method_type))

		return asab.web.rest.json_response(request, {"result": "OK"})


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


	async def _list_password_methods(self, credentials_id: str) -> typing.List[typing.Dict[str, typing.Any]]:
		credentials = await self.CredentialsService.get(credentials_id, include=["__password"])
		if not credentials.get("__password"):
			return []
		else:
			return [self._normalize_password_method(credentials)]


	async def _list_totp_methods(self, credentials_id: str) -> typing.List[typing.Dict[str, typing.Any]]:
		otp_svc = self.App.get_service("seacatauth.OTPService")
		try:
			totp = await otp_svc.get_totp(credentials_id)
		except KeyError:
			return []
		return [self._normalize_totp_method(totp)]


	async def _list_webauthn_methods(self, credentials_id: str) -> typing.List[typing.Dict[str, typing.Any]]:
		methods = []
		webauthn_svc = self.App.get_service("seacatauth.WebAuthnService")
		webauthn_credentials = await webauthn_svc.list_webauthn_credentials(
			credentials_id, rest_normalize=True)
		for cred in webauthn_credentials:
			methods.append(self._normalize_webauthn_method(cred))
		return methods


	async def _list_ext_credential_methods(self, credentials_id: str) -> typing.List[typing.Dict[str, typing.Any]]:
		methods = []
		ext_credentials_svc = self.App.get_service("seacatauth.ExternalCredentialsService")
		ext_credentials = await ext_credentials_svc.list_ext_credentials(credentials_id)
		for ext_credential in ext_credentials:
			methods.append(self._normalize_ext_credential_method(ext_credential))
		return methods


	async def _get_password_method(self, credentials_id: str, method_id: str) -> typing.Dict[str, typing.Any]:
		if credentials_id != method_id:
			raise KeyError()
		try:
			credentials = await self.CredentialsService.get(credentials_id, include=["__password"])
		except exceptions.CredentialsNotFoundError:
			raise KeyError()
		if not credentials.get("__password"):
			raise KeyError()
		return self._normalize_password_method(credentials)


	async def _get_totp_method(self, credentials_id: str, method_id: str) -> typing.Dict[str, typing.Any]:
		if credentials_id != method_id:
			raise KeyError()
		otp_svc = self.App.get_service("seacatauth.OTPService")
		totp = await otp_svc.get_totp(credentials_id)
		return self._normalize_totp_method(totp)


	async def _get_webauthn_method(self, credentials_id: str, method_id: str):
		webauthn_svc = self.App.get_service("seacatauth.WebAuthnService")
		webauthn_credential = await webauthn_svc.get_webauthn_credential(
			webauthn_credential_id=method_id, credentials_id=credentials_id, rest_normalize=True)
		return self._normalize_webauthn_method(webauthn_credential)


	async def _get_ext_credential_method(self, credentials_id: str, method_id: str):
		ext_credentials_svc = self.App.get_service("seacatauth.ExternalCredentialsService")
		ext_credential = await ext_credentials_svc.get_ext_credentials(method_id)
		return self._normalize_ext_credential_method(ext_credential)


	async def _remove_totp_method(self, credentials_id: str, method_id: str):
		if credentials_id != method_id:
			raise KeyError()
		otp_svc = self.App.get_service("seacatauth.OTPService")
		await otp_svc.deactivate_totp(credentials_id=method_id)


	async def _remove_webauthn_method(self, credentials_id: str, method_id: str):
		webauthn_svc = self.App.get_service("seacatauth.WebAuthnService")
		await webauthn_svc.delete_webauthn_credential(
			webauthn_credential_id=method_id, credentials_id=credentials_id)


	async def _remove_ext_credential_method(self, credentials_id: str, method_id: str):
		ext_credentials_svc = self.App.get_service("seacatauth.ExternalCredentialsService")
		await ext_credentials_svc.delete_ext_credentials(method_id)


	def _normalize_password_method(self, credentials: dict) -> dict:
		return {
			"_id": self._make_authn_method_id("password", credentials),
			"type": "password",
			"label": "Password",
		}


	def _normalize_totp_method(self, totp: dict) -> dict:
		return {
			"_id": self._make_authn_method_id("totp", totp),
			"_c": totp.get("_c"),
			"_m": totp.get("_m"),
			"_v": totp.get("_v"),
			"type": "totp",
			"label": "TOTP",
		}


	def _normalize_webauthn_method(self, webauthn_credential: dict) -> dict:
		return {
			"_id": self._make_authn_method_id("webauthn", webauthn_credential),
			"_c": webauthn_credential.get("created"),
			"_m": webauthn_credential.get("_m"),
			"_v": webauthn_credential.get("_v"),
			"type": "webauthn",
			"label": webauthn_credential.get("label") or webauthn_credential.get("name"),
			"last_authentication": webauthn_credential.get("last_login"),
		}


	def _normalize_ext_credential_method(self, ext_credential: dict) -> dict:
		return {
			"_id": self._make_authn_method_id("external", ext_credential),
			"_c": ext_credential.get("_c"),
			"_m": ext_credential.get("_m"),
			"_v": ext_credential.get("_v"),
			"type": "external",
			"label": "{} ({})".format(ext_credential.get("provider_label"), ext_credential.get("label")),
			"details": {
				"external": {
					"provider": ext_credential.get("type"),
					"email": ext_credential.get("email"),
					"username": ext_credential.get("username"),
					"sub": ext_credential.get("sub"),
				}
			},
		}
