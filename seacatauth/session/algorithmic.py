import logging
import jwcrypto.jwt
import jwcrypto.jws
import jwcrypto.jwk
import uuid
import json
import datetime

import asab.exceptions
import asab.web.rest

from .adapter import SessionAdapter
from ..authz import build_credentials_authz

L = logging.getLogger(__name__)


class AlgorithmicSessionProvider:
	"""
	Provide algorithmic session serialization and deserialization.
	"""
	Type = "algorithmic"

	def __init__(self, app):
		self.ClientService = None
		self.CredentialsService = None
		self.TenantService = None
		self.RoleService = None
		self.JSONDumper = asab.web.rest.json.JSONDumper(pretty=False)

		# TODO: Derive the private key
		self.PrivateKey = app.PrivateKey


	async def initialize(self, app):
		self.ClientService = app.get_service("seacatauth.ClientService")
		self.TenantService = app.get_service("seacatauth.TenantService")
		self.RoleService = app.get_service("seacatauth.RoleService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")


	async def deserialize(self, token_value) -> SessionAdapter | None:
		"""
		Parse JWT token and build a SessionAdapter using the token data.
		"""
		try:
			token = jwcrypto.jwt.JWT(jwt=token_value, key=self.PrivateKey)
		except ValueError:
			# This is not a JWToken
			return None
		except (jwcrypto.jws.InvalidJWSSignature, jwcrypto.jwt.JWTExpired) as e:
			# JWToken invalid
			raise asab.exceptions.NotAuthenticatedError() from e

		data_dict = json.loads(token.claims)
		client_dict = await self.ClientService.get(data_dict["azp"])
		try:
			session = await self.create_anonymous_session(
				created_at=datetime.datetime.fromtimestamp(data_dict["iat"], datetime.timezone.utc),
				track_id=uuid.UUID(data_dict["track_id"]).bytes,
				client_dict=client_dict,
				scope=data_dict["scope"])
		except Exception as e:
			raise asab.exceptions.NotAuthenticatedError() from e

		return session


	async def create_anonymous_session(self, created_at, track_id, client_dict, scope):
		tenants = await self.TenantService.get_tenants(client_dict["anonymous_cid"])
		requested_tenants = await self.TenantService.get_tenants_by_scope(
			scope, client_dict["anonymous_cid"])
		authz = await build_credentials_authz(
			self.TenantService, self.RoleService, client_dict["anonymous_cid"], requested_tenants)
		session_dict = {
			SessionAdapter.FN.SessionId: SessionAdapter.ALGORITHMIC_SESSION_ID,
			SessionAdapter.FN.Version: None,
			SessionAdapter.FN.CreatedAt: created_at,
			SessionAdapter.FN.ModifiedAt: created_at,
			SessionAdapter.FN.Session.TrackId: track_id,
			SessionAdapter.FN.OAuth2.ClientId: client_dict["_id"],
			SessionAdapter.FN.OAuth2.Scope: scope,
			SessionAdapter.FN.Credentials.Id: client_dict["anonymous_cid"],
			SessionAdapter.FN.Authentication.IsAnonymous: True,
			SessionAdapter.FN.Authorization.Tenants: tenants,
			SessionAdapter.FN.Authorization.Authz: authz,
		}
		return SessionAdapter(self, session_dict)


	def serialize(self, session: SessionAdapter) -> str:
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


	async def build_algorithmic_session_from_token(self, token_value):
		try:
			token = jwcrypto.jwt.JWT(jwt=token_value, key=self.PrivateKey)
		except ValueError:
			# This is not a JWToken
			return None
		except (jwcrypto.jws.InvalidJWSSignature, jwcrypto.jwt.JWTExpired) as e:
			# JWToken invalid
			raise asab.exceptions.NotAuthenticatedError() from e

		data_dict = json.loads(token.claims)
		client_dict = await self.ClientService.get(data_dict["azp"])
		try:
			session = await self.create_anonymous_session(
				created_at=datetime.datetime.fromtimestamp(data_dict["iat"], datetime.timezone.utc),
				track_id=uuid.UUID(data_dict["track_id"]).bytes,
				client_dict=client_dict,
				scope=data_dict["scope"])
		except Exception as e:
			raise asab.exceptions.NotAuthenticatedError() from e

		return session
