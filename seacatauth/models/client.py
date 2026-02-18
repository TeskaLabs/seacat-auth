import dataclasses
import typing
import datetime
import logging

from .. import generic


L = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class Client:
	_raw: dict  # TEMPORARY. Original raw data from the database, used for integrity checks and updates. Not included in serialization.

	# OAuth/OIDC attributes
	client_id: str
	client_name: str | None = None
	client_uri: str | None = None
	redirect_uris: list[str] | None = None
	application_type: str | None = None
	response_types: list[str] | None = None
	grant_types: list[str] | None = None
	token_endpoint_auth_method: str | None = None
	default_max_age: int | None = None
	code_challenge_method: str | None = None
	client_id_issued_at: datetime.datetime | None = None
	redirect_uri_validation_method: str | None = None  # NON-CANONICAL

	# Secret and metadata
	_client_secret: str | None = None  # Hashed client secret, not included in serialization.
	client_secret_expires_at: datetime.datetime | None = None
	client_secret_updated_at: datetime.datetime | None = None

	# Custom Seacat Auth attributes
	updated_at: datetime.datetime | None = None
	version: int | None = None
	managed_by: str | None = None
	cookie_domain: str | None = None
	cookie_webhook_uri: str | None = None
	cookie_entry_uri: str | None = None
	authorize_uri: str | None = None
	login_uri: str | None = None
	authorize_anonymous_users: bool | None = None
	anonymous_cid: str | None = None
	session_expiration: int | None = None
	seacatauth_credentials: bool | None = None
	credentials_id: str | None = None
	login_key: str | None = None  # TODO: Obsolete (?)

	# Fields supplied by ClientService, not the provider
	cookie_name: str | None = None

	# Any extra fields not explicitly listed
	extra: dict[str, typing.Any] = dataclasses.field(default_factory=dict)

	# TEMPORARY
	def __getitem__(self, key):
		return self._raw[key]

	# TEMPORARY
	def get(self, __key, __default=None):
		return self._raw.get(__key, __default)

	# TEMPORARY
	def items(self):
		return self._raw.items()

	# TEMPORARY
	def __iter__(self):
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

	def verify_secret(self, client_secret: str) -> bool:
		"""
		Checks if the provided client_secret is valid and not expired.
		Returns True if valid, False otherwise.
		"""
		if self.client_secret_expires_at is not None:
			now = datetime.datetime.now(datetime.timezone.utc)
			if now > self.client_secret_expires_at:
				L.error("Expired client secret.", struct_data={"client_id": self.client_id})
				return False
		if self._client_secret is None:
			return False
		return generic.argon2_verify(hash=self._client_secret, secret=client_secret)

	def rest_serialize(self) -> dict:
		"""
		Return a dict of all not-None attributes, replacing __client_secret with client_secret: bool.
		"""
		result = {}
		for k, v in dataclasses.asdict(self).items():
			if k.startswith("_"):
				if k in ("_id", "_v", "_c", "_m"):
					result[k] = v
				elif k == "_raw":
					pass
				elif k == "_client_secret":
					result["client_secret"] = v is not None
				continue
			if v is None:
				continue
			result[k] = v
		if self.is_read_only():
			result["read_only"] = True
		return result
