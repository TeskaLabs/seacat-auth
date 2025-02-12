import logging

import asab
import asab.exceptions
import asab.web.auth
import asab.web.auth.providers
import asab.web.auth.providers.key_providers
import asab.exceptions

from .exceptions import SessionNotFoundError
from .session import SessionAdapter


L = logging.getLogger(__name__)


class Authorization(asab.web.auth.Authorization):
	def __init__(self, claims: dict, session: SessionAdapter):
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
		key_provider = asab.web.auth.providers.key_providers.StaticPublicKeyProvider(app)
		key_provider.set_public_key(app.PrivateKey.public())
		self.register_key_provider(key_provider)


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
