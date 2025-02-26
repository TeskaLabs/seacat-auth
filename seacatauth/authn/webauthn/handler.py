import base64
import logging
import aiohttp.web
import asab.web
import asab.web.rest

from ... import exceptions
from ...decorators import access_control
from . import schema


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


	@access_control()
	async def get_registration_options(self, request):
		"""
		Get WebAuthn registration options
		"""
		try:
			options = await self.WebAuthnService.get_registration_options(request.Session)
		except exceptions.AccessDeniedError:
			return asab.web.rest.json_response(request, data={"status": "FAILED"}, status=400)
		return aiohttp.web.Response(body=options, content_type="application/json")
	# return asab.web.rest.json_response(request, options)


	@asab.web.rest.json_schema_handler(schema.REGISTER_WEBAUTHN_CREDENTIAL)
	@access_control()
	async def register_credential(self, request, *, json_data):
		"""
		Register a new WebAuthn credential for the current user
		"""
		response = await self.WebAuthnService.register_credential(request.Session, public_key_credential=json_data)
		return asab.web.rest.json_response(
			request, response,
			status=200 if response["result"] == "OK" else 400
		)

	@access_control()
	async def list_credentials(self, request, *, credentials_id):
		"""
		List current user's registered WebAuthn credentials
		"""
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
			"result": "OK",
			"data": wa_credentials,
			"count": len(wa_credentials),
		})

	@asab.web.rest.json_schema_handler(schema.UPDATE_WEBAUTHN_CREDENTIAL)
	@access_control()
	async def update_credential(self, request, *, json_data, credentials_id):
		"""
		Update current user's registered WebAuthn credential's metadata
		"""
		try:
			wacid = base64.urlsafe_b64decode(request.match_info["wacid"].encode("ascii") + b"==")
		except ValueError:
			# TODO: Use asab.exceptions.ValidationError instead
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

	@access_control()
	async def remove_credential(self, request, *, credentials_id):
		"""
		Remove current user's registered WebAuthn credential
		"""
		try:
			wacid = base64.urlsafe_b64decode(request.match_info["wacid"].encode("ascii") + b"==")
		except ValueError:
			# TODO: Use asab.exceptions.ValidationError instead
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
