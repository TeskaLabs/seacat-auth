import base64
import logging
import asab.web
import asab.web.auth
import asab.web.rest
import asab.web.tenant
import asab.contextvars

from .. import schema


L = logging.getLogger(__name__)


class WebAuthnAdminHandler(object):
	"""
	Manage FIDO2 Web Authentication

	---
	tags: ["FIDO2/WebAuthn"]
	"""

	def __init__(self, app, webauthn_svc):
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.WebAuthnService = webauthn_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/admin/credentials/{credentials_id}/authn/webauthn", self.admin_list_credentials)
		web_app.router.add_get("/admin/credentials/{credentials_id}/authn/webauthn/{passkey_id}", self.admin_get_credential)
		web_app.router.add_put("/admin/credentials/{credentials_id}/authn/webauthn/{passkey_id}", self.admin_update_credential)
		web_app.router.add_delete("/admin/credentials/{credentials_id}/authn/webauthn/{passkey_id}", self.admin_remove_credential)


	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
	async def admin_list_credentials(self, request):
		"""
		List target user's registered WebAuthn credentials
		"""
		credentials_id = request.match_info["credentials_id"]
		wa_credentials = []
		for credential in await self.WebAuthnService.list_webauthn_credentials(credentials_id, rest_normalize=True):
			wa_credential = {
				"id": base64.urlsafe_b64encode(credential["_id"]).decode("ascii").rstrip("="),
				"name": credential["name"],
				"sign_count": credential["sc"],
				"created": credential["_c"],
			}
			if "ll" in credential:
				wa_credential["last_login"] = credential["ll"]
			wa_credentials.append(wa_credential)

		return asab.web.rest.json_response(request, {
			"data": wa_credentials,
			"count": len(wa_credentials),
		})


	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
	async def admin_get_credential(self, request):
		"""
		Get target user's WebAuthn credential's metadata
		"""
		credentials_id = request.match_info["credentials_id"]
		try:
			passkey_id = base64.urlsafe_b64decode(request.match_info["passkey_id"].encode("ascii") + b"==")
		except ValueError:
			raise KeyError("WebAuthn credential not found", {"passkey_id": request.match_info["passkey_id"]})

		try:
			wa_credential = await self.WebAuthnService.get_webauthn_credential(
				credentials_id, passkey_id, rest_normalize=True)
		except KeyError:
			raise KeyError("WebAuthn credential not found", {
				"passkey_id": passkey_id,
				"cid": credentials_id,
			})
		return asab.web.rest.json_response(request, wa_credential)


	@asab.web.auth.require_superuser
	@asab.web.rest.json_schema_handler(schema.UPDATE_WEBAUTHN_CREDENTIAL)
	@asab.web.tenant.allow_no_tenant
	async def admin_update_credential(self, request, *, json_data):
		"""
		Update target user's WebAuthn credential's metadata
		"""
		credentials_id = request.match_info["credentials_id"]
		try:
			passkey_id = base64.urlsafe_b64decode(request.match_info["passkey_id"].encode("ascii") + b"==")
		except ValueError:
			raise KeyError("WebAuthn credential not found", {"passkey_id": request.match_info["passkey_id"]})

		try:
			await self.WebAuthnService.update_webauthn_credential(
				passkey_id,
				name=json_data["name"],
				credentials_id=credentials_id
			)
		except KeyError:
			raise KeyError("WebAuthn credential not found", {
				"passkey_id": passkey_id,
				"cid": credentials_id,
			})
		return asab.web.rest.json_response(
			request, {"result": "OK"}
		)


	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
	async def admin_remove_credential(self, request):
		"""
		Delete target user's WebAuthn credential
		"""
		credentials_id = request.match_info["credentials_id"]
		try:
			passkey_id = base64.urlsafe_b64decode(request.match_info["passkey_id"].encode("ascii") + b"==")
		except ValueError:
			raise KeyError("WebAuthn credential not found", {"passkey_id": request.match_info["passkey_id"]})

		try:
			await self.WebAuthnService.delete_webauthn_credential(passkey_id, credentials_id)
		except KeyError:
			raise KeyError("WebAuthn credential not found", {
				"passkey_id": passkey_id,
				"cid": credentials_id,
			})

		return asab.web.rest.json_response(
			request, {"result": "OK"}
		)
