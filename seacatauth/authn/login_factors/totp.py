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
		return await otp_service.has_activated_totp(cred_id)

	async def authenticate(self, login_session, request_data) -> bool:
		L.warning("ENTERED authenticate")
		otp_service = self.AuthenticationService.App.get_service("seacatauth.OTPService")
		credentials_id = login_session.CredentialsId
		return otp_service.verify_request_totp(credentials_id, request_data)
