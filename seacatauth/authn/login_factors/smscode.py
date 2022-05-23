import logging

from .abc import LoginFactorABC
from ...generic import generate_ergonomic_token

#

L = logging.getLogger(__name__)

#


class SMSCodeFactor(LoginFactorABC):
	Type = "smscode"

	async def is_eligible(self, login_data) -> bool:
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
		# If SMS Token is not present, generate it
		# Otherwise just resend the existing one
		if self.Type not in login_session.Data:
			login_session.Data[self.Type] = {
				"token": generate_ergonomic_token(length=6)
			}
		token = login_session.Data[self.Type]["token"]
		await self.AuthenticationService.update_login_session(login_session.Id, data=login_session.Data)

		# Get phone number
		cred_svc = self.AuthenticationService.CredentialsService
		credentials = await cred_svc.get(login_session.CredentialsId)
		phone = credentials.get("phone")

		# Send SMS
		comm_svc = self.AuthenticationService.CommunicationService
		success = await comm_svc.sms_login(phone=phone, otp=token)
		if not success:
			L.error("Unable to send SMS login code.", struct_data={
				"cid": login_session.CredentialsId,
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
