import contextlib
import datetime
import logging
import typing
import secrets
import aiohttp.web
import jwcrypto.jwt
import jwcrypto.jwk
import jwcrypto.jws
import asab
import asab.exceptions
import asab.web.auth
import asab.web.auth.providers
import asab.web.auth.providers.key_providers
import asab.exceptions

from .exceptions import SessionNotFoundError
from .models import Session


L = logging.getLogger(__name__)


class Authorization(asab.web.auth.Authorization):
	def __init__(self, claims: dict, session: Session):
		super().__init__(claims)
		self.Session = session


class AsabAuthProvider(asab.web.auth.providers.IdTokenAuthProvider):
	"""
	Custom provider for ASAB AuthService that authenticates and authorizes requests using Seacat Auth API directly.
	"""
	Type = "seacat_auth"

	def __init__(self, app):
		super().__init__(app)
		self.SessionService = app.get_service("seacatauth.SessionService")

		# Add Seacat Auth application key
		key_provider = asab.web.auth.providers.key_providers.StaticPublicKeyProvider(app)
		self.register_key_provider(key_provider)
		key_provider.set_public_key(app.PrivateKey.public())


	async def authorize(self, request: aiohttp.web.Request) -> Authorization:
		bearer_token = asab.web.auth.utils.get_bearer_token_from_authorization_header(request)
		authz = await self._build_authorization(bearer_token)
		return authz


	async def _build_authorization(self, id_token: str) -> Authorization:
		"""
		Build authorization from ID token.

		Args:
			id_token: Base64-encoded JWToken from Authorization header

		Returns:
			Valid asab.web.auth.Authorization object
		"""
		# Try if the object already exists
		authz = self.Authorizations.get(id_token)
		if authz is not None:
			try:
				authz.require_valid()
			except asab.exceptions.NotAuthenticatedError as e:
				del self.Authorizations[id_token]
				raise e
			return authz

		# Create a new Authorization object and store it
		claims = await self._get_claims_from_id_token(id_token)

		# Pair authorization with Seacat Auth session
		try:
			session = self.SessionService.get(claims["sid"])
		except SessionNotFoundError:
			L.error("Session not found.", struct_data={"sid": claims["sid"]})
			raise asab.exceptions.NotAuthenticatedError()

		authz = Authorization(claims, session)

		self.Authorizations[id_token] = authz
		return authz


	async def _get_claims_from_id_token(self, id_token):
		"""
		Parse the bearer ID token and extract auth claims.
		"""
		try:
			return asab.web.auth.utils.get_id_token_claims(id_token, self.TrustedJwkSet)
		except (jwcrypto.jws.InvalidJWSSignature, jwcrypto.jwt.JWTMissingKey) as e:
			L.error("Cannot authenticate request: {}".format(str(e)))
			raise asab.exceptions.NotAuthenticatedError()


@contextlib.contextmanager
def system_authz(
	issuer: str,
	resources: typing.Collection[str],
	tenant: str | None,
	expiration: int = 60
) -> Authorization:
	if tenant is None:
		tenant = "*"
	authorized_resources = {
		tenant: set(resources),
	}
	session_id = secrets.token_urlsafe(16)
	now = datetime.datetime.now(datetime.UTC)
	session_dict = {
		Session.FN.SessionId: session_id,
		Session.FN.Version: 0,
		Session.FN.CreatedAt: now,
		Session.FN.ModifiedAt: None,
		Session.FN.Session.Type: "SYSTEM",
		Session.FN.Session.Expiration: now + datetime.timedelta(seconds=expiration),
		Session.FN.Authorization.Authz: authorized_resources,
		Session.FN.Credentials.Id: "SYSTEM",
	}
	session = Session(session_dict)

	claims = {
		"resources": authorized_resources,
		"sid": session_id,
		"iss": issuer,
		"iat": now.timestamp(),
		"exp": now.timestamp() + expiration,
	}
	authz = Authorization(claims, session)

	authz_ctx = asab.contextvars.Authz.set(authz)
	try:
		yield authz
	finally:
		asab.contextvars.Authz.reset(authz_ctx)
		del authz
		del session
