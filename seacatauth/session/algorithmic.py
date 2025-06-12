import logging
import typing
import jwcrypto.jwt
import jwcrypto.jws
import jwcrypto.jwk
import uuid
import json
import datetime
import asab.web.rest
import asab.metrics

from ..models import Session
from .. import exceptions
from ..authz import build_credentials_authz


L = logging.getLogger(__name__)


class AlgorithmicSessionProvider:
	"""
	Provide algorithmic session serialization and deserialization.

	A variation of OAuth's "self-encoded access tokens"
	https://www.oauth.com/oauth2-servers/access-tokens/self-encoded-access-tokens/
	"""
	Type = "algorithmic"

	def __init__(self, app):
		self.MetricsService = app.get_service("asab.MetricsService")
		self.ClientService = None
		self.CredentialsService = None
		self.TenantService = None
		self.RoleService = None
		self.JSONDumper = asab.web.rest.json.JSONDumper(pretty=False)

		# TODO: Derive the private key
		self.PrivateKey = app.PrivateKey

		# Database request optimization.
		# Maps (credentials_id, scope) to available_tenants and authz.
		self.AuthzCache: typing.Dict[typing.Tuple[str, frozenset], dict] = {}
		self.AuthzCacheExpiration = datetime.timedelta(
			seconds=asab.Config.getseconds("seacatauth:session", "algo_cache_expiration"))

		self.AnonymousSessionCounter: asab.metrics.Counter = self.MetricsService.create_counter(
			"anonymous_sessions",
			tags={"help": "Number of anonymous sessions created."},
			init_values={"sessions": 0})


	async def initialize(self, app):
		self.ClientService = app.get_service("seacatauth.ClientService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")


	async def create_anonymous_session(
		self, created_at, track_id, client_dict, scope,
		redirect_uri: str = None
	) -> Session:
		session = await self._build_anonymous_session(created_at, track_id, client_dict, scope, redirect_uri)
		self.AnonymousSessionCounter.add("sessions", 1)
		return session

	async def _build_anonymous_session(
		self, created_at, track_id, client_dict, scope,
		redirect_uri: str = None
	) -> Session:
		session_dict = {
			Session.FN.SessionId: Session.ALGORITHMIC_SESSION_ID,
			Session.FN.Version: None,
			Session.FN.CreatedAt: created_at,
			Session.FN.ModifiedAt: created_at,
			Session.FN.Session.TrackId: track_id,
			Session.FN.OAuth2.ClientId: client_dict["_id"],
			Session.FN.OAuth2.Scope: scope,
			Session.FN.Credentials.Id: client_dict["anonymous_cid"],
			Session.FN.Authentication.IsAnonymous: True,
		}
		await self._add_session_authz(session_dict, client_dict["anonymous_cid"], scope)
		return Session(session_dict)


	async def _add_session_authz(self, session_dict: dict, credentials_id: str, scope: set):
		"""
		Updates the session dict with tenant and resource authorization based on scope.
		"""
		data = self.AuthzCache.get((credentials_id, frozenset(scope)))
		if data and datetime.datetime.now(datetime.timezone.utc) < data["exp"]:
			available_tenants = data["available_tenants"]
			authz = data["authz"]
		else:
			available_tenants = await self.TenantService.get_tenants(credentials_id)
			requested_tenants = await self.TenantService.get_tenants_by_scope(
				scope, credentials_id)
			authz = await build_credentials_authz(
				self.TenantService, self.RoleService, credentials_id, requested_tenants)
			self.AuthzCache[(credentials_id, frozenset(scope))] = {
				"exp": datetime.datetime.now(datetime.timezone.utc) + self.AuthzCacheExpiration,
				"available_tenants": available_tenants,
				"authz": authz
			}

		session_dict[Session.FN.Authorization.AssignedTenants] = available_tenants
		session_dict[Session.FN.Authorization.Authz] = authz


	async def deserialize(self, token_value) -> Session | None:
		"""
		Parse JWT token and build a SessionAdapter using the token data.
		"""
		try:
			token = jwcrypto.jwt.JWT(jwt=token_value, key=self.PrivateKey)
		except (ValueError, jwcrypto.jws.InvalidJWSObject) as e:
			L.error("Corrupt algorithmic session token.")
			raise exceptions.SessionNotFoundError("Corrupt algorithmic session token.") from e
		except jwcrypto.jws.InvalidJWSSignature as e:
			L.error("Invalid algorithmic session token signature.")
			raise exceptions.SessionNotFoundError("Invalid algorithmic session token signature.") from e
		except jwcrypto.jwt.JWTExpired as e:
			raise exceptions.SessionNotFoundError("Expired algorithmic session token.") from e

		data_dict = json.loads(token.claims)
		client_dict = await self.ClientService.get_client(data_dict["azp"])
		try:
			session = await self._build_anonymous_session(
				created_at=datetime.datetime.fromtimestamp(data_dict["iat"], datetime.timezone.utc),
				track_id=uuid.UUID(data_dict["track_id"]).bytes,
				client_dict=client_dict,
				scope=data_dict["scope"])
		except Exception as e:
			L.error(
				"Failed to build session from algorithmic session token claims.", struct_data=data_dict)
			raise exceptions.SessionNotFoundError(
				"Failed to build session from algorithmic session token claims.") from e

		return session


	def serialize(self, session: Session) -> str:
		"""
		Serialize SessionAdapter into a minimal JWT token string.
		"""
		if not session.Session.TrackId:
			session.Session.TrackId = uuid.uuid4().bytes
		payload = {
			"iat": int(session.CreatedAt.timestamp()),
			"azp": session.OAuth2.ClientId,
			"scope": session.OAuth2.Scope,
			"track_id": session.Session.TrackId.hex(),
		}
		header = {
			"alg": "ES256",
			"typ": "JWT",
			"kid": self.PrivateKey.key_id,
		}
		token = jwcrypto.jwt.JWT(
			header=header,
			claims=self.JSONDumper(payload)
		)
		token.make_signed_token(self.PrivateKey)
		id_token = token.serialize()
		return id_token
