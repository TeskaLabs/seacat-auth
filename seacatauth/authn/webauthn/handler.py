import base64
import logging
import aiohttp.web
import asab.web
import asab.web.rest
import asab.web.tenant
import asab.contextvars

from ... import exceptions


L = logging.getLogger(__name__)


class WebAuthnHandler(object):
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
		web_app.router.add_delete("/account/webauthn/{wacid}", self.remove_credential)
		web_app.router.add_put("/account/webauthn/{wacid}", self.update_credential)
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


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": [
			"id",
			"rawId",
			"response",
			"type",
		],
		"properties": {
			"id": {
				# Credentials ID
				"type": "string"
			},
			"rawId": {
				# The ID again, but in binary form
				"type": "string"
			},
			"response": {
				# The actual WebAuthn login data
				"type": "object",
				"required": [
					"clientDataJSON",
					"attestationObject",
				],
				"properties": {
					"clientDataJSON": {"type": "string"},
					"attestationObject": {"type": "string"},
				}
			},
			"type": {
				"type": "string",
				"enum": ["public-key"],
			},
		}
	})
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
		wa_credentials = []
		for credential in await self.WebAuthnService.list_webauthn_credentials(authz.CredentialsId):
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
			"result": "OK",
			"data": wa_credentials,
			"count": len(wa_credentials),
		})


	@asab.web.rest.json_schema_handler({
		"type": "object",
		"required": [
			"name",
		],
		"properties": {
			"name": {
				"type": "string",
				"minLength": 3,
				"maxLength": 128,
			},
		}
	})
	@asab.web.tenant.allow_no_tenant
	async def update_credential(self, request, *, json_data):
		"""
		Update current user's registered WebAuthn credential's metadata
		"""
		authz = asab.contextvars.Authz.get()
		try:
			wacid = base64.urlsafe_b64decode(request.match_info["wacid"].encode("ascii") + b"==")
		except ValueError:
			raise KeyError("WebAuthn credential not found", {"wacid": request.match_info["wacid"]})

		try:
			await self.WebAuthnService.update_webauthn_credential(
				wacid,
				name=json_data["name"],
				credentials_id=authz.CredentialsId
			)
		except KeyError:
			raise KeyError("WebAuthn credential not found", {
				"wacid": wacid,
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
			wacid = base64.urlsafe_b64decode(request.match_info["wacid"].encode("ascii") + b"==")
		except ValueError:
			raise KeyError("WebAuthn credential not found", {"wacid": request.match_info["wacid"]})

		try:
			await self.WebAuthnService.delete_webauthn_credential(wacid, authz.CredentialsId)
		except KeyError:
			raise KeyError("WebAuthn credential not found", {
				"wacid": wacid,
				"cid": authz.CredentialsId,
			})

		return asab.web.rest.json_response(
			request, {"result": "OK"}
		)
