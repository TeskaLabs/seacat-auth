import logging
import jwcrypto.jwt
import jwcrypto.jws
import jwcrypto.jwk
import uuid
import json
import datetime

import asab.exceptions

from .adapter import SessionAdapter


L = logging.getLogger(__name__)


class AlgorithmicSessionProvider:
	Type = "algorithmic"


	def __init__(self, app):
		self.ClientService = None
		self.CredentialsService = None
		self.JSONDumper = asab.web.rest.json.JSONDumper(pretty=False)

		# TODO: Derive the private key
		self.PrivateKey = app.PrivateKey


	async def initialize(self, app):
		self.ClientService = app.get_service("seacatauth.ClientService")
		self.CredentialsService = app.get_service("seacatauth.CredentialsService")


	async def get_session(self, token_value, client_dict, scope):
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
			session = self.create_algorithmic_anonymous_session(
				created_at=datetime.datetime.fromtimestamp(data_dict["iat"], datetime.timezone.utc),
				track_id=uuid.UUID(data_dict["track_id"]).bytes,
				client_dict=client_dict,
				scope=data_dict["scope"])
		except Exception as e:
			raise asab.exceptions.NotAuthenticatedError() from e

		return session


	def create_algorithmic_anonymous_session(self, created_at, track_id, client_dict, scope):
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
			SessionAdapter.FN.Authorization.Tenants: ["default"],  # FIXME: Get tenants by scope
			SessionAdapter.FN.Authorization.Authz: {"default": ["blabla"]},  # FIXME: Get resources by scope
		}
		return SessionAdapter(self, session_dict)


	def build_algorithmic_session_token(self, session):
		payload = {
			"iat": int(session.CreatedAt.timestamp()),
			"azp": session.OAuth2.ClientId,
			"scope": session.OAuth2.Scope,
			"track_id": uuid.UUID(bytes=session.Session.TrackId),
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
			session = self.build_algorithmic_anonymous_session(
				created_at=datetime.datetime.fromtimestamp(data_dict["iat"], datetime.timezone.utc),
				track_id=uuid.UUID(data_dict["track_id"]).bytes,
				client_dict=client_dict,
				scope=data_dict["scope"])
		except Exception as e:
			raise asab.exceptions.NotAuthenticatedError() from e

		return session
