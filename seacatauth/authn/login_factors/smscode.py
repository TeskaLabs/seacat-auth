import logging

from .abc import LoginFactorABC
from ...generic import generate_ergonomic_token

#

L = logging.getLogger(__name__)

#


class SMSCodeFactor(LoginFactorABC):
	Type = "smscode"

	async def is_eligible(self, login_data) -> bool:
		if not self.AuthenticationService.CommunicationService.is_enabled("sms"):
			# SMS provider is not configured
			return False

		cred_svc = self.AuthenticationService.CredentialsService
		cred_id = login_data["credentials_id"]
		if cred_id == "":
			# Not eligible for "fake" login session
			return False
		credentials = await cred_svc.get(cred_id, include=["phone"])
		phone = credentials.get("phone")
		if phone is not None and len(phone) > 0:
			return True
		return False

	async def set_phone(self, credentials_id, phone):
		provider = self.AuthenticationService.CredentialsService.get_provider(credentials_id)
		await provider.update(credentials_id, {"phone": phone})

	async def send_otp(self, login_session) -> bool:
		"""
		Generate one-time passcode and send it in an SMS.
		Return True if the SMS delivery succeeds.
		"""
		login_data = login_session.SeacatLogin.Data
		# If SMS Token is not present, generate it
		# Otherwise just resend the existing one
		if self.Type not in login_data:
			token = generate_ergonomic_token(length=6)
			login_data[self.Type] = {"token": token}
			login_session = await self.AuthenticationService.update_login_session(login_session, data=login_data)
		else:
			token = login_data["token"]

		# Get phone number
		cred_svc = self.AuthenticationService.CredentialsService
		credentials = await cred_svc.get(login_session.SeacatLogin.CredentialsId)
		phone = credentials.get("phone")
		assert phone is not None

		# Send SMS
		comm_svc = self.AuthenticationService.CommunicationService
		try:
			await comm_svc.sms_login(credentials=credentials, otp=token)
		except Exception as e:
			L.error("Unable to send SMS login code: {}".format(e), struct_data={
				"cid": login_session.SeacatLogin.CredentialsId,
				"lsid": login_session.Id,
				"phone": phone,
			})
			return False
		return True

	async def authenticate(self, login_session, request_data) -> bool:
		if self.Type not in request_data or self.Type not in login_session.Data:
			return False
		user_input = request_data[self.Type].strip()
		token = login_session.Data[self.Type]["token"]
		if token is not None and user_input == token:
			return True
		return False
