import logging
import re
import secrets
import urllib.parse

import asab.storage.exceptions
import asab.exceptions

from .. import exceptions

#

L = logging.getLogger(__name__)

#


class OAuth2ClientService(asab.Service):
	ClientCollection = "cl"
	ClientIdPattern = r"[a-z][a-z0-9._-]{2,31}"
	ClientSecretLength = 32
	ClientIdLength = 32

	def __init__(self, app, service_name="seacatauth.ClientService"):
		super().__init__(app, service_name)
		self.StorageService = app.get_service("asab.StorageService")
		self.ClientIdRegex = re.compile("^{}$".format(self.ClientIdPattern))


	async def initialize(self, app):
		await super().initialize(app)
		# TODO: Auto-create clients for Seacat UI etc.


	async def list(self, page: int = 0, limit: int = None, query_filter: dict = None, include: list = None):
		collection = self.StorageService.Database[self.ClientCollection]

		if query_filter is None:
			query_filter = {}
		cursor = collection.find(query_filter)

		cursor.sort("_c", -1)
		if limit is not None:
			cursor.skip(limit * page)
			cursor.limit(limit)

		clients = []
		count = await collection.count_documents(query_filter)
		async for data in cursor:
			clients.append(self.normalize_client(data, include))

		return {
			"data": clients,
			"count": count,
		}


	async def get(self, client_id: str, include: list = None):
		client = await self.StorageService.get(self.ClientCollection, client_id)
		client = self.normalize_client(client, include)
		# TODO: Generate authorize URIs for the client (for convenience)
		return client


	def normalize_client(self, data, include):
		"""
		Remove confidential client data
		"""
		return {
			k: v
			for k, v in data
			if not k.startswith("__") or k in include
		}


	async def create(
		self,
		client_name: str,
		client_type: str,
		redirect_uris: list = None,
		client_description: str = None,
		allowed_scopes: list = None,
		logout_uri: str = None,
	):
		"""
		Create a new OAuth2 client

		:param client_name: Human readable name of the client
		:type client_name: str
		:param client_type: The type of the client. Can be either 'confidential' or 'public'
		:type client_type: str
		:param redirect_uris: Allowed redirect URIs
		:type redirect_uris: list
		:param client_description: A description of the client (optional)
		:type client_description: str
		:param allowed_scopes: A list of allowed scopes (optional)
		:type allowed_scopes: list
		:param logout_uri: Application URI to be called on logout (optional)
		:type logout_uri: str
		:return: The generated client_id and client_secret.
		"""

		# https://datatracker.ietf.org/doc/html/rfc6749#section-2.2
		# The authorization server issues the registered client a client
		# identifier -- a unique string representing the registration
		# information provided by the client
		client_id = secrets.token_urlsafe(self.ClientIdLength)
		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id)

		# https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
		# OAuth defines two client types, based on their ability to
		# authenticate securely with the authorization server (i.e., ability to
		# maintain the confidentiality of their client credentials):
		if client_type == "confidential":
			# Clients capable of maintaining the confidentiality of their
			# credentials (e.g., client implemented on a secure server with
			# restricted access to the client credentials), or capable of secure
			# client authentication using other means.

			# Confidential clients are typically issued (or establish) a set of
			# client credentials used for authenticating with the authorization
			# server (e.g., password, public/private key pair).
			client_secret = secrets.token_urlsafe(self.ClientSecretLength)
			# TODO: Encrypt secret
			upsertor.set("__cs", client_secret)
		elif client_type == "public":
			# Clients incapable of maintaining the confidentiality of their
			# credentials (e.g., clients executing on the device used by the
			# resource owner, such as an installed native application or a web
			# browser-based application), and incapable of secure client
			# authentication via any other means.

			# The authorization server MAY establish a client authentication method
			# with public clients. However, the authorization server MUST NOT rely
			# on public client authentication for the purpose of identifying the
			# client.
			client_secret = ""
			upsertor.set("__cs", client_secret)
		else:
			raise asab.exceptions.ValidationError(
				"Unknown client type '{}'. Allowed types: 'confidential', 'public'".format(client_type)
			)

		upsertor.set("ct", client_type)

		if redirect_uris is None:
			redirect_uris = []
		else:
			# Validate URIs
			# https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
			# The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3.
			# The endpoint URI MUST NOT include a fragment component.
			for uri in redirect_uris:
				parsed = urllib.parse.urlparse(uri)
				if len(parsed.netloc) == 0 or len(parsed.scheme) == 0 or len(parsed.fragment) == 0:
					raise asab.exceptions.ValidationError(
						"Redirect URI must be an absolute URI without a fragment component "
						"(as defined by RFC3986 Section 4.3)."
					)

		upsertor.set("ru", redirect_uris)

		upsertor.set("cn", client_name)

		if client_description is not None:
			upsertor.set("cd", client_description)

		if allowed_scopes is not None:
			upsertor.set("as", allowed_scopes)  # TODO: Validate

		if logout_uri is not None:
			upsertor.set("lu", logout_uri)

		try:
			await upsertor.execute()
			L.log(asab.LOG_NOTICE, "OAuth2 client ID created", struct_data={
				"client_id": client_id,
				"client_name": client_name,
			})
		except asab.storage.exceptions.DuplicateError:
			raise asab.exceptions.Conflict(key="client_id", value=client_id)

		response = {
			"client_id": client_id,
		}

		if client_secret is not None:
			response["client_secret"] = client_secret

		return response


	async def reset_secret(self, client_id: str):
		try:
			client = await self.get(client_id)
		except KeyError:
			raise exceptions.InvalidClientID(client_id)
		if client["ct"] != "confidential":
			L.warning("Setting secret for non-confidential OAuth2 client", struct_data={
				"client_id": client_id,
			})
		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id)
		client_secret = secrets.token_urlsafe(self.ClientSecretLength)
		upsertor.set("cs", client_secret)
		return client_secret


	async def update(
		self,
		client_id: str,
		client_name: str,
		redirect_uris: list = None,
		client_description: str = None,
		allowed_scopes: list = None,
		logout_uri: str = None,
	):
		upsertor = self.StorageService.upsertor(self.ClientCollection, obj_id=client_id)

		if redirect_uris is not None:
			upsertor.set("ru", list(redirect_uris))  # TODO: Validate

		if client_name is not None:
			upsertor.set("cn", client_name)

		if client_description is not None:
			upsertor.set("cd", client_description)

		if allowed_scopes is not None:
			upsertor.set("as", allowed_scopes)  # TODO: Validate

		if logout_uri is not None:
			upsertor.set("lu", logout_uri)

		await upsertor.execute()
		L.log(asab.LOG_NOTICE, "OAuth2 client updated", struct_data={"client_id": client_id})


	async def delete(self, client_id: str):
		self.StorageService.delete(self.ClientCollection, client_id)
		L.log(asab.LOG_NOTICE, "OAuth2 client deleted", struct_data={"client_id": client_id})


	async def authorize_client(
		self,
		client_id: str,
		scope: list,
		redirect_uri: str,
		client_secret: str = None,
	):
		try:
			registered_client = await self.get(client_id, include=frozenset(["__cs"]))
		except KeyError:
			raise exceptions.InvalidClientID(client_id)

		if client_secret is None:
			# The client MAY omit the parameter if the client secret is an empty string.
			# (rfc6749#section-2.3.1)
			client_secret = ""
		if client_secret != registered_client.get("__cs", ""):
			raise exceptions.InvalidClientSecret(client_id)

		if redirect_uri not in registered_client["ru"]:
			raise exceptions.ForbiddenRedirectURI(client_id, redirect_uri)

		allowed_scopes = registered_client.get("s")
		if allowed_scopes is not None:
			for scope_item in scope:
				if scope_item not in allowed_scopes:
					raise exceptions.ForbiddenScope(client_id, scope)

		return True
