import logging

from .abc import LoginFactorABC

#

L = logging.getLogger(__name__)

#


class WebAuthnFactor(LoginFactorABC):
	Type = "webauthn"

	async def is_eligible(self, login_data) -> bool:
		cred_svc = self.AuthenticationService.CredentialsService
		cred_id = login_data["credentials_id"]
		if cred_id == "":
			# Not eligible for "fake" login session
			return False
		credentials = await cred_svc.get(cred_id, include=frozenset(["__webauthn"]))
		public_key = credentials.get("__webauthn", "")
		if len(public_key) > 0:
			return True
		return False

	async def authenticate(self, login_session, request_data) -> bool:
		webauthn_svc = self.AuthenticationService.App.get_service("seacatauth.WebAuthnService")
		return False
