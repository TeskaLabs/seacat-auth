import base64
import hashlib
import re
import logging
import asab.exceptions

from seacatauth.session import SessionAdapter

#

L = logging.getLogger(__name__)

#


class Authentication:
	"""
	Processes authentication preferences (AMR and ACR values)
	"""

	# Authentication Method Reference
	# https://www.rfc-editor.org/rfc/rfc8176.html
	LoginFactorAmrValues = {
		"password": "pwd",
		"smscode": "sms",
		"totp": "otp",
		"webauthn": "hwk",
	}


	def __init__(self, app):
		self.StorageService = app.get_service("asab.StorageService")
		self.ClientService = None
		self.AuthenticationService = None
		self.ExternalLoginService = None


	async def initialize(self, app):
		self.ClientService = app.get_service("seacatauth.ClientService")
		self.AuthenticationService = app.get_service("seacatauth.AuthenticationService")
		self.ExternalLoginService = app.get_service("seacatauth.ExternalLoginService")


	async def prepare_login_uri(
		self,
		root_session: SessionAdapter | None,
		client_id: dict,
		authorization_query: dict,
		acr_values: list
	):
		"""
		Build the URI of Seacat Auth login or external provider login page with callback to authorization request
		"""
		if acr_values:
			for acr_value in acr_values:
				# Return the first valid URL
				# At the moment, ACR values are used only for external login preferences
				if acr_value.startswith("ext:"):
					login_uri = await self.ExternalLoginService.prepare_external_login_url(
						acr_value, root_session, authorization_query)
					if login_uri:
						return login_uri

		# Otherwise use standard Seacat Auth login
		return await self.AuthenticationService.prepare_seacat_login_url(client_id, authorization_query)


	def is_login_required(
		self,
		root_session: SessionAdapter | None = None,
		allow_anonymous: bool = False,
		prompt: str | None = None,
		acr_values: list | None = None,
	) -> bool:
		if prompt == "login":
			L.log(asab.LOG_NOTICE, "Client requested 'login' prompt")
			return True
		elif prompt == "select_account":
			L.log(asab.LOG_NOTICE, "Client requested 'select_account' prompt")
			return True
		elif root_session is None or root_session.is_anonymous():
			if allow_anonymous:
				return False
			else:
				L.log(asab.LOG_NOTICE, "Client does not allow anonymous access")
				return True
		elif not self.are_acr_preferences_satisfied(root_session, acr_values):
			L.log(asab.LOG_NOTICE, "Client requested a different authentication class", struct_data={
				"acr_values": acr_values})
			return True
		else:
			return False


	def acr_values_supported(self) -> list:
		"""
		List supported authentication class preferences (ACR values)
		"""
		acr_values = []
		# TODO: Add options for other login types/descriptors (2fa, mfa, basic...)

		# Add external login options
		acr_values.extend(self.ExternalLoginService.acr_values_supported())
		return acr_values


	def are_acr_preferences_satisfied(self, session: SessionAdapter | None, acr_values: list) -> bool:
		"""
		Verify if the session's authentication satisfies requested preferences (OIDC ACR values)
		"""
		if session is None or not session.OAuth2.ACR:
			# Session is missing or has no authentication data
			return False

		if not acr_values:
			# No authentication preferences specified
			return True

		# At least one authentication preference must be satisfied
		for acr_value in acr_values:
			# Only the "ext"-prefixed values are supported for now
			if acr_value.startswith("ext:") and acr_value in session.OAuth2.ACR:
				return True

		return False
