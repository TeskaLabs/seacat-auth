from .abc import LoginFactorABC


class PasswordFactor(LoginFactorABC):
	Type = "password"

	async def is_eligible(self, login_data: dict) -> bool:
		"""
		PasswordFactor is always eligible, since all credentials are required to have a password (for now).
		"""
		return True

	async def authenticate(self, login_session, request_data) -> bool:
		cred_svc = self.AuthenticationService.CredentialsService
		return await cred_svc.authenticate(login_session.CredentialsId, request_data)
