import logging

import asab

from .abc import LoginFactorABC

#

L = logging.getLogger(__name__)

#


class WebAuthnFactor(LoginFactorABC):
	Type = "webauthn"

	async def is_eligible(self, login_data) -> bool:
		"""
		User is eligible for WebAuthn login if they have at least one WebAuthn credential registered
		"""
		credentials_id = login_data["credentials_id"]
		if credentials_id == "":
			# Not eligible for "fake" login session
			return False
		webauthn_svc = self.AuthenticationService.App.get_service("seacatauth.WebAuthnService")
		webauthn_credentials = await webauthn_svc.list_webauthn_credentials(credentials_id)
		if len(webauthn_credentials) > 0:
			return True
		return False

	async def authenticate(self, login_session, request_data) -> bool:
		if "webauthn" not in request_data:
			L.log(asab.LOG_NOTICE, "No webauthn data in login request", struct_data={
				"lsid": login_session.Id, "cid": login_session.CredentialsId})
			return False
		public_key_credential = request_data["webauthn"]

		webauthn_svc = self.AuthenticationService.App.get_service("seacatauth.WebAuthnService")
		return await webauthn_svc.authenticate_credential(
			login_session.CredentialsId,
			login_session.Data.get("webauthn"),
			public_key_credential
		)
