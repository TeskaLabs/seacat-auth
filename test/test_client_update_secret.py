import datetime
import json
import unittest
from unittest.mock import patch

from seacatauth.client.handler import ClientHandler
from seacatauth.client.service import ClientService
from seacatauth.models.const import OAuth2


def _client(**overrides):
	client = {
		"_id": "cid",
		"_v": 1,
		"client_name": "App",
		"redirect_uris": ["https://app.example/callback"],
		"application_type": "web",
		"grant_types": [OAuth2.GrantType.AUTHORIZATION_CODE],
		"response_types": [OAuth2.ResponseType.CODE],
		"token_endpoint_auth_method": OAuth2.TokenEndpointAuthMethod.NONE,
	}
	client.update(overrides)
	return client


class _Provider:

	def __init__(self, client):
		self.client = client
		self.updates = []

	async def get_client(self, client_id):
		if self.client.get("_id") != client_id:
			raise KeyError(client_id)
		return self.client

	async def update_client(self, client_id, **client_data):
		self.updates.append(client_data)
		for key, value in client_data.items():
			if value is None:
				self.client.pop(key, None)
			else:
				self.client[key] = value


def _service(provider):
	svc = object.__new__(ClientService)
	svc.DefaultProviderId = "default"
	svc.ClientProviders = {"default": provider}
	svc.Cache = {}
	svc.ClientSecretExpiration = None
	svc._AllowInsecureWebClientURIs = False
	svc._generate_client_secret = lambda: ("generated-secret", None)
	return svc


class UpdateClientSecretTestCase(unittest.IsolatedAsyncioTestCase):

	async def test_public_to_confidential_without_secret_issues_secret(self):
		provider = _Provider(_client(
			token_endpoint_auth_method=OAuth2.TokenEndpointAuthMethod.NONE,
			client_secret_expires_at=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
		))
		svc = _service(provider)

		with patch("seacatauth.client.service.generic.argon2_hash", return_value="hashed") as hash_secret:
			secret, expires_at = await svc.update_client(
				"cid",
				token_endpoint_auth_method=OAuth2.TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
			)

		self.assertEqual(secret, "generated-secret")
		self.assertIsNone(expires_at)
		hash_secret.assert_called_once_with("generated-secret")
		self.assertEqual(provider.client["__client_secret"], "hashed")
		self.assertNotIn("client_secret_expires_at", provider.client)
		self.assertIn("client_secret_updated_at", provider.client)

	async def test_missing_auth_method_without_secret_issues_secret(self):
		client = _client()
		del client["token_endpoint_auth_method"]
		provider = _Provider(client)
		svc = _service(provider)

		with patch("seacatauth.client.service.generic.argon2_hash", return_value="hashed"):
			secret, _ = await svc.update_client(
				"cid",
				token_endpoint_auth_method=OAuth2.TokenEndpointAuthMethod.CLIENT_SECRET_POST,
			)

		self.assertEqual(secret, "generated-secret")
		self.assertEqual(provider.client["__client_secret"], "hashed")

	async def test_missing_auth_method_with_secret_to_client_secret_post_keeps_secret(self):
		client = _client(__client_secret="hashed")
		del client["token_endpoint_auth_method"]
		provider = _Provider(client)
		svc = _service(provider)

		secret, _ = await svc.update_client(
			"cid",
			token_endpoint_auth_method=OAuth2.TokenEndpointAuthMethod.CLIENT_SECRET_POST,
		)

		self.assertIsNone(secret)
		self.assertEqual(provider.client["__client_secret"], "hashed")
		self.assertNotIn("__client_secret", provider.updates[0])

	async def test_public_with_secret_to_confidential_keeps_secret(self):
		provider = _Provider(_client(
			token_endpoint_auth_method=OAuth2.TokenEndpointAuthMethod.NONE,
			__client_secret="hashed",
			client_secret_expires_at=datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc),
		))
		svc = _service(provider)

		secret, _ = await svc.update_client(
			"cid",
			token_endpoint_auth_method=OAuth2.TokenEndpointAuthMethod.CLIENT_SECRET_POST,
		)

		self.assertIsNone(secret)
		self.assertEqual(provider.client["__client_secret"], "hashed")
		self.assertEqual(
			provider.client["client_secret_expires_at"],
			datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc),
		)
		self.assertNotIn("__client_secret", provider.updates[0])

	async def test_missing_auth_method_with_secret_to_none_keeps_secret(self):
		client = _client(
			__client_secret="hashed",
			client_secret_expires_at=datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc),
			client_secret_updated_at=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
		)
		del client["token_endpoint_auth_method"]
		provider = _Provider(client)
		svc = _service(provider)

		secret, expires_at = await svc.update_client(
			"cid",
			token_endpoint_auth_method=OAuth2.TokenEndpointAuthMethod.NONE,
		)

		self.assertIsNone(secret)
		self.assertIsNone(expires_at)
		self.assertEqual(provider.client["__client_secret"], "hashed")
		self.assertIn("client_secret_expires_at", provider.client)
		self.assertIn("client_secret_updated_at", provider.client)
		self.assertNotIn("__client_secret", provider.updates[0])

	async def test_confidential_to_public_keeps_secret(self):
		provider = _Provider(_client(
			token_endpoint_auth_method=OAuth2.TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
			__client_secret="hashed",
			client_secret_expires_at=datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc),
			client_secret_updated_at=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
		))
		svc = _service(provider)

		secret, expires_at = await svc.update_client(
			"cid",
			token_endpoint_auth_method=OAuth2.TokenEndpointAuthMethod.NONE,
		)

		self.assertIsNone(secret)
		self.assertIsNone(expires_at)
		self.assertEqual(provider.client["__client_secret"], "hashed")
		self.assertIn("client_secret_expires_at", provider.client)
		self.assertIn("client_secret_updated_at", provider.client)
		self.assertNotIn("__client_secret", provider.updates[0])

	async def test_confidential_method_switch_keeps_secret(self):
		provider = _Provider(_client(
			token_endpoint_auth_method=OAuth2.TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
			__client_secret="hashed",
		))
		svc = _service(provider)

		secret, _ = await svc.update_client(
			"cid",
			token_endpoint_auth_method=OAuth2.TokenEndpointAuthMethod.CLIENT_SECRET_POST,
		)

		self.assertIsNone(secret)
		self.assertEqual(provider.client["__client_secret"], "hashed")
		self.assertNotIn("__client_secret", provider.updates[0])

	async def test_unrelated_update_keeps_secret(self):
		provider = _Provider(_client(
			token_endpoint_auth_method=OAuth2.TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
			__client_secret="hashed",
		))
		svc = _service(provider)

		secret, _ = await svc.update_client("cid", client_name="Renamed")

		self.assertIsNone(secret)
		self.assertEqual(provider.client["__client_secret"], "hashed")
		self.assertEqual(provider.client["token_endpoint_auth_method"], OAuth2.TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)
		self.assertNotIn("__client_secret", provider.updates[0])

	async def test_public_to_public_does_not_issue_secret(self):
		provider = _Provider(_client())
		svc = _service(provider)

		secret, _ = await svc.update_client(
			"cid",
			token_endpoint_auth_method=OAuth2.TokenEndpointAuthMethod.NONE,
		)

		self.assertIsNone(secret)
		self.assertNotIn("__client_secret", provider.client)
		self.assertNotIn("__client_secret", provider.updates[0])


def _unwrap(func):
	while hasattr(func, "__wrapped__"):
		func = func.__wrapped__
	return func


class UpdateClientResponseTestCase(unittest.IsolatedAsyncioTestCase):

	async def _update(self, secret, client):
		handler = object.__new__(ClientHandler)

		async def update_client(client_id, **kwargs):
			return secret

		async def get_client(client_id):
			return client

		handler.ClientService = type("Svc", (), {
			"update_client": staticmethod(update_client),
			"get_client": staticmethod(get_client),
		})()
		request = type("Req", (), {
			"match_info": {"client_id": "cid"},
			"query": {},
		})()
		response = await _unwrap(ClientHandler.update_client)(
			handler,
			request,
			json_data={"token_endpoint_auth_method": "client_secret_basic"},
		)
		return json.loads(response.body)

	async def test_reset_returns_plaintext_secret_instead_of_bool(self):
		expires_at = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
		body = await self._update(
			("generated-secret", expires_at),
			{
				"client_id": "cid",
				"client_name": "App",
				"client_secret": True,
				"token_endpoint_auth_method": "client_secret_basic",
			},
		)
		self.assertEqual(body["result"], "OK")
		self.assertEqual(body["client_secret"], "generated-secret")
		self.assertIsInstance(body["client_secret"], str)
		self.assertEqual(body["client_secret_expires_at"], expires_at.isoformat().replace("+00:00", "Z"))

	async def test_unchanged_secret_stays_bool(self):
		body = await self._update(
			(None, None),
			{
				"client_id": "cid",
				"client_secret": True,
				"token_endpoint_auth_method": "client_secret_basic",
			},
		)
		self.assertEqual(body["result"], "OK")
		self.assertIs(body["client_secret"], True)

	async def test_removed_secret_is_absent(self):
		body = await self._update(
			(None, None),
			{
				"client_id": "cid",
				"token_endpoint_auth_method": "none",
			},
		)
		self.assertEqual(body["result"], "OK")
		self.assertNotIn("client_secret", body)
