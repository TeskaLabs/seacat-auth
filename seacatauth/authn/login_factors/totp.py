import logging

from .abc import LoginFactorABC
from ...otp import authn_totp

#

L = logging.getLogger(__name__)

#


class TOTPFactor(LoginFactorABC):
	Type = "totp"

	async def is_eligible(self, login_data: dict) -> bool:
		# Check if OTP is set up in credentials
		cred_svc = self.AuthenticationService.CredentialsService
		cred_id = login_data["credentials_id"]
		if cred_id == "":
			# Not eligible for "fake" login session
			return False
		credentials = await cred_svc.get(cred_id, include=frozenset(["__totp"]))
		totp = credentials.get("__totp", "")
		if len(totp) > 0:
			return True
		return False

	async def authenticate(self, login_session, request_data) -> bool:
		cred_svc = self.AuthenticationService.CredentialsService
		cred_id = login_session.CredentialsId
		credentials = await cred_svc.get(cred_id, include=frozenset(["__totp"]))
		return authn_totp(credentials, request_data)
