# TODO: Restructure. This is OAuth, but not OpenID Connect!
import base64
import hashlib
import re
import logging

#

L = logging.getLogger(__name__)

#


class CodeChallengeFailedError(Exception):
	pass


class InvalidCodeChallengeMethodError(Exception):
	def __init__(self, client_id, code_challenge_method, *args, **kwargs):
		self.ClientID = client_id
		self.CodeChallengeMethod = code_challenge_method
		super().__init__("Invalid code_challenge_method for client", *args)


class PKCE:
	CODE_VERIFIER_PATTERN = re.compile("^[A-Za-z0-9._~-]{43,128}$")

	@classmethod
	def verify_code_challenge_method(cls, client: dict, code_challenge_method: str):
		if code_challenge_method is None:
			code_challenge_method = "plain"

		allowed_methods = client.get("code_challenge_methods")
		if allowed_methods is None or len(allowed_methods) == 0:
			# TODO: If the client has no code_challenge_methods registered, raise an error
			# If the client is capable of using "S256", it MUST use "S256", as
			# "S256" is Mandatory To Implement (MTI) on the server.
			# https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
			L.warning("Client has no 'code_challenge_methods' registered.", struct_data={"client_id": client["_id"]})
		elif code_challenge_method not in allowed_methods:
			raise InvalidCodeChallengeMethodError(
				client_id=client["_id"], code_challenge_method=code_challenge_method)
		else:
			# Method is valid for this client
			pass

	@classmethod
	def evaluate_code_challenge(cls, code_challenge_method, code_challenge, code_verifier):
		"""
		https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
		"""
		if cls.CODE_VERIFIER_PATTERN.match(code_verifier) is None:
			raise CodeChallengeFailedError("Code Verifier does not match the required pattern (RFC7636 section 4.1).")
	
		if code_challenge_method == "plain":
			request_challenge = code_verifier
		elif code_challenge_method == "S256":
			request_challenge = base64.urlsafe_b64encode(
				hashlib.sha256(code_verifier.encode("ascii")).digest()).decode("ascii")
		else:
			raise CodeChallengeFailedError("Unsupported code_challenge_method: {!r}".format(code_challenge_method))
	
		if request_challenge != code_challenge:
			raise CodeChallengeFailedError("Code Challenge does not match.")
	
	
