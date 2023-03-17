import unittest

from seacatauth.client.service import validate_redirect_uri


class OAuthUriTestCase(unittest.TestCase):
	maxDiff = None

	def test_exact_match(self):
		registered_uris = ["https://abc.test/def/ghi?jkl=mno&pqr=stu"]
		requested_uri = "https://abc.test/def/ghi?jkl=mno&pqr=stu"
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "prefix_match"))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "none"))

	def test_reordered_query(self):
		registered_uris = ["https://abc.test/def/ghi?jkl=mno&pqr=stu"]
		requested_uri = "https://abc.test/def/ghi?pqr=stu&jkl=mno"
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris))
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris, "prefix_match"))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "none"))

	def test_extra_query(self):
		registered_uris = ["https://abc.test/def/ghi"]
		requested_uri = "https://abc.test/def/ghi?jkl=mno"
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "prefix_match"))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "none"))

		registered_uris = ["https://abc.test/def/ghi?jkl=mno&pqr=stu"]
		requested_uri = "https://abc.test/def/ghi?jkl=mno&pqr=stu&vwx=yz"
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "prefix_match"))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "none"))

	def test_extra_fragment(self):
		registered_uris = ["https://abc.test/def/ghi?jkl=mno&pqr=stu"]
		requested_uri = "https://abc.test/def/ghi?jkl=mno&pqr=stu#xyz"
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "prefix_match"))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "none"))

	def test_extra_path(self):
		registered_uris = ["https://abc.test"]
		requested_uri = "https://abc.test/def/ghi"
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "prefix_match"))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "none"))

		registered_uris = ["https://abc.test/def"]
		requested_uri = "https://abc.test/def/ghi"
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "prefix_match"))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "none"))

	def test_scheme_mismatch(self):
		registered_uris = ["https://abc.test"]
		requested_uri = "http://abc.test"
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "prefix_match"))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "none"))

	def test_extra_trailing_slash(self):
		registered_uris = ["https://abc.test"]
		requested_uri = "https://abc.test/"
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "prefix_match"))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "none"))

	def test_missing_trailing_slash(self):
		registered_uris = ["https://abc.test/"]
		requested_uri = "https://abc.test"
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris))
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris, "prefix_match"))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "none"))

	def test_same_prefix_netloc(self):
		registered_uris = ["https://abc.test"]
		requested_uri = "https://abc.test.elsewhere.test"
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris))
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris, "prefix_match"))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "none"))

	def test_extra_port(self):
		registered_uris = ["https://abc.test"]
		requested_uri = "https://abc.test:8080"
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "prefix_match"))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "none"))

	def test_different_port(self):
		registered_uris = ["https://abc.test:80"]
		requested_uri = "https://abc.test:8080"
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris))
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris, "prefix_match"))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "none"))

	def test_subdomain(self):
		registered_uris = ["https://abc.test"]
		requested_uri = "https://subdomain.abc.test"
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris))
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris, "prefix_match"))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "none"))

	def test_same_prefix_path(self):
		registered_uris = ["https://abc.test/path"]
		requested_uri = "https://abc.test/pathetic"
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris))
		self.assertFalse(validate_redirect_uri(requested_uri, registered_uris, "prefix_match"))
		self.assertTrue(validate_redirect_uri(requested_uri, registered_uris, "none"))
