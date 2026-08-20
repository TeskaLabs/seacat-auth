import unittest

from seacatauth.openidconnect.cors import (
	apply_oauth_cors_headers,
	is_oauth_api_path,
	oauth_cors_headers,
)


class _FakeClientService:
	def __init__(self, allowed_origins):
		self.allowed_origins = set(allowed_origins)

	def is_origin_allowed(self, origin):
		return origin in self.allowed_origins


class _FakeRequest:
	def __init__(self, path, origin=None):
		self.path = path
		self.headers = {}
		if origin is not None:
			self.headers["Origin"] = origin


class _FakeResponse:
	def __init__(self):
		self.headers = {}


class OAuthCorsTestCase(unittest.TestCase):

	def test_oauth_api_paths(self):
		self.assertTrue(is_oauth_api_path("/openidconnect/token"))
		self.assertTrue(is_oauth_api_path("/openidconnect/userinfo"))
		self.assertTrue(is_oauth_api_path("/.well-known/openid-configuration"))
		self.assertTrue(is_oauth_api_path("/.well-known/jwks.json"))
		self.assertTrue(is_oauth_api_path("/.well-known/oauth-protected-resource/foo"))
		self.assertFalse(is_oauth_api_path("/public/login"))
		self.assertFalse(is_oauth_api_path("/admin/client"))

	def test_allowed_origin_gets_cors_headers(self):
		origin = "https://app.example.com"
		request = _FakeRequest("/openidconnect/token", origin=origin)
		response = _FakeResponse()
		apply_oauth_cors_headers(request, response, _FakeClientService({origin}))

		self.assertEqual(response.headers["Access-Control-Allow-Origin"], origin)
		self.assertEqual(response.headers["Access-Control-Allow-Credentials"], "true")
		self.assertIn("X-App", response.headers["Access-Control-Allow-Headers"])
		self.assertIn("X-Request-Id", response.headers["Access-Control-Allow-Headers"])
		self.assertIn("Authorization", response.headers["Access-Control-Allow-Headers"])
		self.assertEqual(response.headers["Vary"], "Origin")

	def test_unknown_origin_has_no_cors_headers(self):
		request = _FakeRequest("/openidconnect/token", origin="https://evil.example")
		response = _FakeResponse()
		apply_oauth_cors_headers(request, response, _FakeClientService({"https://app.example.com"}))
		self.assertEqual(response.headers, {})

	def test_non_oauth_path_is_untouched(self):
		origin = "https://app.example.com"
		request = _FakeRequest("/public/login", origin=origin)
		response = _FakeResponse()
		apply_oauth_cors_headers(request, response, _FakeClientService({origin}))
		self.assertEqual(response.headers, {})

	def test_header_list(self):
		headers = oauth_cors_headers("https://app.example.com")
		self.assertEqual(
			headers["Access-Control-Allow-Headers"],
			"Authorization, Content-Type, X-App, X-Request-Id",
		)
		self.assertIn("PUT", headers["Access-Control-Allow-Methods"])
