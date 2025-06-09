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
		web_app.router.add_get("/admin/credentials/{credentials_id}/webauthn", self.admin_list_credentials)
		web_app.router.add_put("/admin/credentials/{credentials_id}/webauthn/{wacid}", self.admin_update_credential)
		web_app.router.add_delete("/admin/credentials/{credentials_id}/webauthn/{wacid}", self.admin_remove_credential)


	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
	async def admin_list_credentials(self, request):
		"""
		List target user's registered WebAuthn credentials
		"""
		credentials_id = request.match_info["credentials_id"]
		wa_credentials = []
		for credential in await self.WebAuthnService.list_webauthn_credentials(credentials_id):
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
	@asab.web.rest.json_schema_handler(schema.UPDATE_WEBAUTHN_CREDENTIAL)
	@asab.web.tenant.allow_no_tenant
	async def admin_update_credential(self, request, *, json_data):
		"""
		Update current user's registered WebAuthn credential's metadata
		"""
		credentials_id = request.match_info["credentials_id"]
		try:
			wacid = base64.urlsafe_b64decode(request.match_info["wacid"].encode("ascii") + b"==")
		except ValueError:
			raise KeyError("WebAuthn credential not found", {"wacid": request.match_info["wacid"]})

		try:
			await self.WebAuthnService.update_webauthn_credential(
				wacid,
				name=json_data["name"],
				credentials_id=credentials_id
			)
		except KeyError:
			raise KeyError("WebAuthn credential not found", {
				"wacid": wacid,
				"cid": credentials_id,
			})
		return asab.web.rest.json_response(
			request, {"result": "OK"}
		)


	@asab.web.auth.require_superuser
	@asab.web.tenant.allow_no_tenant
	async def admin_remove_credential(self, request):
		"""
		Remove current user's registered WebAuthn credential
		"""
		credentials_id = request.match_info["credentials_id"]
		try:
			wacid = base64.urlsafe_b64decode(request.match_info["wacid"].encode("ascii") + b"==")
		except ValueError:
			raise KeyError("WebAuthn credential not found", {"wacid": request.match_info["wacid"]})

		try:
			await self.WebAuthnService.delete_webauthn_credential(wacid, credentials_id)
		except KeyError:
			raise KeyError("WebAuthn credential not found", {
				"wacid": wacid,
				"cid": credentials_id,
			})

		return asab.web.rest.json_response(
			request, {"result": "OK"}
		)
