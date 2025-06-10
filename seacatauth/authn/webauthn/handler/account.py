import base64
import logging
import aiohttp.web
import asab.web
import asab.web.rest
import asab.web.tenant
import asab.contextvars

from .... import exceptions
from .. import schema


L = logging.getLogger(__name__)


class WebAuthnAccountHandler(object):
	"""
	Manage FIDO2 Web Authentication

	---
	tags: ["FIDO2/WebAuthn"]
	"""

	def __init__(self, app, webauthn_svc):
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")
		self.WebAuthnService = webauthn_svc

		web_app = app.WebContainer.WebApp
		web_app.router.add_get("/account/webauthn/register-options", self.get_registration_options)
		web_app.router.add_put("/account/webauthn/register", self.register_credential)
		web_app.router.add_get("/account/webauthn/{passkey_id}", self.get_credential)
		web_app.router.add_delete("/account/webauthn/{passkey_id}", self.remove_credential)
		web_app.router.add_put("/account/webauthn/{passkey_id}", self.update_credential)
		web_app.router.add_get("/account/webauthn", self.list_credentials)


	@asab.web.tenant.allow_no_tenant
	async def get_registration_options(self, request):
		"""
		Get WebAuthn registration options
		"""
		authz = asab.contextvars.Authz.get()
		try:
			options = await self.WebAuthnService.get_registration_options(authz.Session)
		except exceptions.AccessDeniedError:
			return asab.web.rest.json_response(request, data={"status": "FAILED"}, status=400)
		return aiohttp.web.Response(body=options, content_type="application/json")



	@asab.web.rest.json_schema_handler(schema.REGISTER_WEBAUTHN_CREDENTIAL)
	@asab.web.tenant.allow_no_tenant
	async def register_credential(self, request, *, json_data):
		"""
		Register a new WebAuthn credential for the current user
		"""
		authz = asab.contextvars.Authz.get()
		response = await self.WebAuthnService.register_credential(authz.Session, public_key_credential=json_data)
		return asab.web.rest.json_response(
			request, response,
			status=200 if response["result"] == "OK" else 400
		)


	@asab.web.tenant.allow_no_tenant
	async def list_credentials(self, request):
		"""
		List current user's registered WebAuthn credentials
		"""
		authz = asab.contextvars.Authz.get()
		wa_credentials = await self.WebAuthnService.list_webauthn_credentials(
			authz.CredentialsId, rest_normalize=True)
		return asab.web.rest.json_response(request, {
			"data": wa_credentials,
			"count": len(wa_credentials),
		})


	@asab.web.tenant.allow_no_tenant
	async def get_credential(self, request):
		"""
		Get current user's registered WebAuthn credential's metadata
		"""
		authz = asab.contextvars.Authz.get()
		try:
			passkey_id = base64.urlsafe_b64decode(request.match_info["passkey_id"].encode("ascii") + b"==")
		except ValueError:
			raise KeyError("WebAuthn credential not found", {"passkey_id": request.match_info["passkey_id"]})

		try:
			wa_credential = await self.WebAuthnService.get_webauthn_credential(
				authz.CredentialsId, passkey_id, rest_normalize=True)
		except KeyError:
			raise KeyError("WebAuthn credential not found", {
				"passkey_id": passkey_id,
				"cid": authz.CredentialsId,
			})
		return asab.web.rest.json_response(request, wa_credential)

	@asab.web.rest.json_schema_handler(schema.UPDATE_WEBAUTHN_CREDENTIAL)
	@asab.web.tenant.allow_no_tenant
	async def update_credential(self, request, *, json_data):
		"""
		Update current user's registered WebAuthn credential's metadata
		"""
		authz = asab.contextvars.Authz.get()
		try:
			passkey_id = base64.urlsafe_b64decode(request.match_info["passkey_id"].encode("ascii") + b"==")
		except ValueError:
			raise KeyError("WebAuthn credential not found", {"passkey_id": request.match_info["passkey_id"]})

		try:
			await self.WebAuthnService.update_webauthn_credential(
				passkey_id,
				name=json_data["name"],
				credentials_id=authz.CredentialsId
			)
		except KeyError:
			raise KeyError("WebAuthn credential not found", {
				"passkey_id": passkey_id,
				"cid": authz.CredentialsId,
			})
		return asab.web.rest.json_response(
			request, {"result": "OK"}
		)


	@asab.web.tenant.allow_no_tenant
	async def remove_credential(self, request):
		"""
		Remove current user's registered WebAuthn credential
		"""
		authz = asab.contextvars.Authz.get()
		try:
			passkey_id = base64.urlsafe_b64decode(request.match_info["passkey_id"].encode("ascii") + b"==")
		except ValueError:
			raise KeyError("WebAuthn credential not found", {"passkey_id": request.match_info["passkey_id"]})

		try:
			await self.WebAuthnService.delete_webauthn_credential(passkey_id, authz.CredentialsId)
		except KeyError:
			raise KeyError("WebAuthn credential not found", {
				"passkey_id": passkey_id,
				"cid": authz.CredentialsId,
			})

		return asab.web.rest.json_response(
			request, {"result": "OK"}
		)
