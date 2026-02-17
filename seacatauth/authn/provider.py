import typing
import abc


class AuthnMethodProviderABC(abc.ABC):
	"""
	Abstract base class for authentication method providers.

	Method schema:
	{
		# The type of the authentication method (e.g., "password", "totp", "webauthn", "external").
		"type": str,

		# The ID of the authentication method. For singleton methods, this should be None.
		"id": str | None,

		# The ID of the credentials associated with this authentication method
		"cid": str,

		# A human-readable label for the authentication method
		"label": str,

		# (Optional) A list of available actions for the authentication method (e.g., ["reset"] for password method, ["delete"] for TOTP method).
		"actions": list[str],

		# (Optional) Provider-specific details about the authentication method
		"details": dict | None,

		# (Optional) Number of times the credential was used
		"usage_count": int | None,

		# (Optional) Timestamp of the last successful authentication.
		"last_authentication": datetime | None,

		# (Optional) Timestamp when the credential was created.
		"created": datetime | None,

		# (Optional) Timestamp of the last failed authentication attempt.
		"last_failed_authentication": datetime | None,

		# (Optional) Count of consecutive failed authentication attempts.
		"failed_attempts": int | None,

		# (Optional) Timestamp of the last update (e.g., name change, key rotation).
		"last_updated": datetime | None,

		# (Optional) IP addresses from which the credential was last used.
		"last_ip": list[str] | None,
	}
	"""
	MethodType = None
	MultipleMethodsPerCredentials = False

	# TODO: Merge with login factors, implement `authenticate` method

	def __init__(self, app, *args, **kwargs):
		self.App = app

	async def initialize(self, app):
		"""
		Initialize the authentication method provider.
		This method is called during application startup and can be used to perform any necessary setup (e.g., database connections, loading configurations).
		"""
		self._register()

	def _register(self):
		"""
		Register this provider with the AuthenticationService.
		"""
		authn_service = self.App.get_service("seacatauth.AuthenticationService")
		authn_service.register_authn_method_provider(self)

	async def iterate_authn_methods(self, credentials_id: str) -> typing.AsyncGenerator[dict, None]:
		"""
		Iterate over active authentication methods for the provided credential ID.

		Args:
			credentials_id: The ID of the credentials to query.
		Yields:
			A dictionary containing the authentication method details (e.g., type, label, actions).
			Only active authentication methods should be yielded.
		"""
		raise NotImplementedError()

	async def get_authn_method(self, credentials_id: str, method_id: str | None = None) -> dict:
		"""
		Get the authentication method details for the provided credentials.

		Args:
			credentials_id: The ID of the credentials to query.
			method_id: The ID of the authentication method to retrieve. For singleton methods, this should be None.
		Returns:
			A dictionary containing the authentication method details (e.g., type, label, actions).
		"""
		raise NotImplementedError()
