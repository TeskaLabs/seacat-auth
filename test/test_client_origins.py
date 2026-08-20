import unittest

from seacatauth.client.service import origin_from_redirect_uri


class OriginFromRedirectUriTestCase(unittest.TestCase):

	def test_https_path_and_query_are_dropped(self):
		self.assertEqual(
			origin_from_redirect_uri("https://app.example.com/callback?x=1"),
			"https://app.example.com",
		)

	def test_http_with_non_default_port(self):
		self.assertEqual(
			origin_from_redirect_uri("http://localhost:3000/callback"),
			"http://localhost:3000",
		)

	def test_default_https_port_is_omitted(self):
		self.assertEqual(
			origin_from_redirect_uri("https://app.example.com:443/callback"),
			"https://app.example.com",
		)

	def test_default_http_port_is_omitted(self):
		self.assertEqual(
			origin_from_redirect_uri("http://localhost:80/callback"),
			"http://localhost",
		)

	def test_custom_scheme_is_ignored(self):
		self.assertIsNone(origin_from_redirect_uri("myapp://callback"))

	def test_missing_host_is_ignored(self):
		self.assertIsNone(origin_from_redirect_uri("/local/callback"))

	def test_ipv6(self):
		self.assertEqual(
			origin_from_redirect_uri("https://[::1]:8443/callback"),
			"https://[::1]:8443",
		)
