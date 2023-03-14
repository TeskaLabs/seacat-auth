import logging

from .abc import LoginFactorABC


#

L = logging.getLogger(__name__)

#


class TOTPFactor(LoginFactorABC):
	Type = "totp"

	async def is_eligible(self, login_data: dict) -> bool:
		"""
		Check if OTP is set up in credentials.
		"""
		otp_service = self.AuthenticationService.App.get_service("seacatauth.OTPService")

		cred_id = login_data["credentials_id"]
		if cred_id == "":
			# Not eligible for "fake" login session
			return False
		credentials = await otp_service.get(cred_id, include=frozenset(["__totp"]))
		totp = credentials.get("__totp", "")
		if len(totp) > 0:
			return True
		return False

	async def authenticate(self, login_session, request_data) -> bool:
		L.warning("ENTERED authenticate")
		otp_service = self.AuthenticationService.App.get_service("seacatauth.OTPService")
		credentials_id = login_session.CredentialsId
		return otp_service.compare_totp_with_request_data(credentials_id, request_data)
