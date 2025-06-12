import base64
import hashlib
import re
import logging
import asab.exceptions

from ..models.const import OAuth2


L = logging.getLogger(__name__)


class CodeChallengeFailedError(Exception):
	pass


class InvalidCodeChallengeMethodError(Exception):
	def __init__(self, client_id, code_challenge_method, *args, **kwargs):
		self.ClientID = client_id
		self.CodeChallengeMethod = code_challenge_method
		super().__init__("Invalid code_challenge_method for client.", *args)


class InvalidCodeChallengeError(Exception):
	def __init__(self, message=None, *, client_id, **kwargs):
		self.ClientID = client_id
		message = message or "Code challenge request is not valid."
		super().__init__(message)


class PKCE:
	"""
	Proof Key for Code Exchange

	https://datatracker.ietf.org/doc/html/rfc7636

	Introduces a code challenge to the OAuth 2.0 Authorization Code Flow
	"""

	CodeVerifierPattern = re.compile("^[A-Za-z0-9._~-]{43,128}$")

	@classmethod
	def validate_code_challenge_method_registration(cls, code_challenge_method: str):
		"""
		Validate whether (any) client can register the requested methods
		"""
		if code_challenge_method not in OAuth2.CodeChallengeMethod:
			raise asab.exceptions.ValidationError(
				"Unsupported Code Challenge Method: {!r}.".format(code_challenge_method))

	@classmethod
	def validate_code_challenge_initialization(
		cls, client: dict, code_challenge: str = None, requested_code_challenge_method: str = None):
		"""
		Validate whether the client can use the requested method in authorization
		"""
		expected_method = client.get("code_challenge_method", OAuth2.CodeChallengeMethod.NONE)
		if requested_code_challenge_method is None:
			# If no specific method is requested, default to the pre-configured client value
			requested_code_challenge_method = expected_method

		# Requested method must be stronger than or equal to the expected method
		if not OAuth2.CodeChallengeMethod.is_stronger_or_equal(requested_code_challenge_method, expected_method):
			raise InvalidCodeChallengeMethodError(
				client_id=client["_id"], code_challenge_method=requested_code_challenge_method)

		if requested_code_challenge_method == "none":
			if code_challenge is not None:
				raise InvalidCodeChallengeError(
					"Cannot use non-empty 'code_challenge' when 'code_challenge_method' is 'none'.",
					client_id=client["_id"],
				)
		else:
			if code_challenge is None:
				raise InvalidCodeChallengeError(
					"Missing 'code_challenge' when 'code_challenge_method' is not 'none'.",
					client_id=client["_id"],
				)

		return requested_code_challenge_method

	@classmethod
	def evaluate_code_challenge(cls, code_challenge_method, code_challenge, code_verifier):
		"""
		Evaluate whether the code challenge was successful

		https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
		"""
		if cls.CodeVerifierPattern.match(code_verifier) is None:
			raise CodeChallengeFailedError("Code Verifier does not match the required pattern (RFC7636 section 4.1).")

		if code_challenge_method == "plain":
			request_challenge = code_verifier
		elif code_challenge_method == "S256":
			request_challenge = base64.urlsafe_b64encode(
				# PKCE uses Base64url Encoding **without Padding**
				# https://datatracker.ietf.org/doc/html/rfc7636#appendix-A
				hashlib.sha256(code_verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
		else:
			raise CodeChallengeFailedError("Unsupported code_challenge_method: {!r}".format(code_challenge_method))

		if request_challenge != code_challenge:
			raise CodeChallengeFailedError("Code Challenge does not pair with the Code Verifier.")
