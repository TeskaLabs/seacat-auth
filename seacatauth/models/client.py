import dataclasses
import typing
import datetime
import inspect

from .. import generic


@dataclasses.dataclass(frozen=True)
class Client:
	_raw: dict  # TEMPORARY. Original raw data from the database, used for integrity checks and updates. Not included in serialization.

	# MongoDB metadata fields
	_id: str
	_v: int
	_c: datetime.datetime
	_m: datetime.datetime

	# Canonical OAuth/OIDC attributes
	client_id: str
	client_name: typing.Optional[str] = None
	client_uri: typing.Optional[str] = None
	redirect_uris: typing.Optional[list[str]] = None
	application_type: typing.Optional[str] = None
	response_types: typing.Optional[list[str]] = None
	grant_types: typing.Optional[list[str]] = None
	token_endpoint_auth_method: typing.Optional[str] = None
	default_max_age: typing.Optional[typing.Union[str, int]] = None
	code_challenge_method: typing.Optional[str] = None
	client_id_issued_at: typing.Optional[datetime.datetime] = None

	# Secret and metadata
	_client_secret: typing.Optional[str] = None
	client_secret_expires_at: typing.Optional[datetime.datetime] = None
	client_secret_updated_at: typing.Optional[datetime.datetime] = None

	# Custom Seacat Auth attributes (NON-CANONICAL)
	managed_by: typing.Optional[str] = None
	cookie_name: typing.Optional[str] = None
	cookie_domain: typing.Optional[str] = None
	cookie_webhook_uri: typing.Optional[str] = None
	cookie_entry_uri: typing.Optional[str] = None
	authorize_uri: typing.Optional[str] = None
	login_uri: typing.Optional[str] = None
	authorize_anonymous_users: typing.Optional[bool] = None
	anonymous_cid: typing.Optional[str] = None
	session_expiration: typing.Optional[typing.Union[str, int]] = None
	redirect_uri_validation_method: typing.Optional[str] = None
	seacatauth_credentials: typing.Optional[bool] = None
	credentials_id: typing.Optional[str] = None
	login_key: typing.Optional[str] = None  # TODO

	# Any extra fields not explicitly listed
	extra: typing.Dict[str, typing.Any] = dataclasses.field(default_factory=dict)

	# TEMPORARY
	def __getitem__(self, key):
		frame = inspect.currentframe()
		outer_frames = inspect.getouterframes(frame)
		# The caller is at index 1
		if len(outer_frames) > 1:
			caller = outer_frames[1]
			print(f"Client.__getitem__ called from File \"{caller.filename}\", line {caller.lineno}")
		return self._raw[key]

	# TEMPORARY
	def get(self, __key, __default=None):
		frame = inspect.currentframe()
		outer_frames = inspect.getouterframes(frame)
		# The caller is at index 1
		if len(outer_frames) > 1:
			caller = outer_frames[1]
			print(f"Client.get called from File \"{caller.filename}\", line {caller.lineno}")
		return self._raw.get(__key, __default)

	# TEMPORARY
	def items(self):
		frame = inspect.currentframe()
		outer_frames = inspect.getouterframes(frame)
		# The caller is at index 1
		if len(outer_frames) > 1:
			caller = outer_frames[1]
			print(f"Client.items called from File \"{caller.filename}\", line {caller.lineno}")
		return self._raw.items()

	# TEMPORARY
	def __iter__(self):
		frame = inspect.currentframe()
		outer_frames = inspect.getouterframes(frame)
		# The caller is at index 1
		if len(outer_frames) > 1:
			caller = outer_frames[1]
			print(f"Client.__iter__ called from File \"{caller.filename}\", line {caller.lineno}")
		return self._raw.__iter__()

	def is_oauth2_client(self) -> bool:
		"""
		Returns True if the client has the minimal required OAuth2 fields.
		Minimal required fields: client_name and redirect_uris (non-empty list).
		"""
		if not self.client_name:
			return False
		if not self.redirect_uris or not isinstance(self.redirect_uris, list) or len(self.redirect_uris) == 0:
			return False
		return True

	def is_read_only(self) -> bool:
		"""
		Returns True if the client is managed by an external system and should not be modified directly through the API.
		"""
		return self.managed_by is not None

	def authenticate(self, client_secret: str) -> bool:
		"""
		Checks if the provided client_secret is valid and not expired.
		Returns True if valid, False otherwise.
		"""
		if self.client_secret_expires_at is not None:
			now = datetime.datetime.now(datetime.timezone.utc)
			if now > self.client_secret_expires_at:
				return False
		if self._client_secret is None:
			return False
		return generic.argon2_verify(client_secret, self._client_secret)

	def rest_serialize(self) -> dict:
		"""
		Return a dict of all not-None attributes, replacing __client_secret with client_secret: bool.
		"""
		result = {}
		for k, v in dataclasses.asdict(self).items():
			if k == "__raw":
				continue
			if k == "__client_secret":
				result["client_secret"] = v is not None
				continue
			if v is None:
				continue
			result[k] = v
		if self.is_read_only():
			result["read_only"] = True
		return result
