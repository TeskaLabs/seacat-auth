import unittest
import unittest.mock
import os
import urllib.parse
from unittest.mock import MagicMock, patch, PropertyMock


class AppUrlPreparationTestCase(unittest.TestCase):
	"""
	Test suite for SeaCatAuthApplication URL preparation logic.
	Tests the _prepare_public_urls method including backward compatibility,
	validation, and URL resolution.
	"""
	maxDiff = None

	def setUp(self):
		"""Set up test fixtures"""
		self.config_patches = []
		self.log_patches = []

	def tearDown(self):
		"""Clean up patches"""
		for patcher in self.config_patches + self.log_patches:
			patcher.stop()

	def _mock_config(self, config_values):
		"""
		Helper to mock asab.Config.get() with specific values.
		
		Args:
			config_values: Dict mapping (section, key) tuples to values
		"""
		def config_get(section, key, fallback=None):
			return config_values.get((section, key), fallback)
		
		patcher = patch('asab.Config.get', side_effect=config_get)
		mock_config = patcher.start()
		self.config_patches.append(patcher)
		return mock_config

	def _create_mock_app(self, config_values):
		"""
		Create a mock application with mocked configuration.
		
		Args:
			config_values: Dict mapping (section, key) tuples to values
		"""
		self._mock_config(config_values)
		
		# Mock LogObsolete
		log_obsolete_patcher = patch('asab.LogObsolete')
		mock_log_obsolete = log_obsolete_patcher.start()
		self.log_patches.append(log_obsolete_patcher)
		
		# Mock LOG_NOTICE
		log_notice_patcher = patch('asab.LOG_NOTICE', 20)
		log_notice_patcher.start()
		self.log_patches.append(log_notice_patcher)
		
		# Create mock app
		with patch('seacatauth.app.asab.Application.__init__', return_value=None):
			from seacatauth.app import SeaCatAuthApplication
			app = object.__new__(SeaCatAuthApplication)
			app.PublicUrl = None
			app.AuthWebUiApiBaseUrl = None
			app.PublicOpenIdConnectApiUrl = None
			app.AuthWebUiUrl = None
			return app, mock_log_obsolete

	def test_auth_webui_api_base_url_absolute_https(self):
		"""Test AuthWebUiApiBaseUrl with absolute HTTPS URL"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'https://example.com/auth/api/seacat-auth/',
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'https://example.com/auth/',
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		self.assertEqual(app.AuthWebUiApiBaseUrl, 'https://example.com/auth/api/seacat-auth/')
		self.assertEqual(app.AuthWebUiUrl, 'https://example.com/auth/')
		self.assertTrue(app.AuthWebUiApiBaseUrl.startswith(app.AuthWebUiUrl))

	def test_auth_webui_api_base_url_relative(self):
		"""Test AuthWebUiApiBaseUrl with relative URL"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'auth/api/seacat-auth/',
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'auth/',
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		self.assertEqual(app.AuthWebUiApiBaseUrl, 'https://example.com/auth/api/seacat-auth/')
		self.assertEqual(app.AuthWebUiUrl, 'https://example.com/auth/')
		self.assertTrue(app.AuthWebUiApiBaseUrl.startswith(app.AuthWebUiUrl))

	def test_auth_webui_api_base_url_trailing_slash_added(self):
		"""Test that trailing slash is added to AuthWebUiApiBaseUrl"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'auth/api/seacat-auth',  # No trailing slash
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'auth/',
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		self.assertEqual(app.AuthWebUiApiBaseUrl, 'https://example.com/auth/api/seacat-auth/')
		self.assertTrue(app.AuthWebUiApiBaseUrl.endswith('/'))

	def test_backward_compatibility_public_seacat_auth_base_url(self):
		"""Test backward compatibility with old config name"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'auth/api/seacat-auth/',
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'auth/',
			('general', 'public_seacat_auth_base_url'): 'api/seacat-auth/',  # Old config name
		}
		
		app, mock_log_obsolete = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		# Should use the old config value
		self.assertEqual(app.AuthWebUiApiBaseUrl, 'https://example.com/api/seacat-auth/')
		
		# Should log obsolete warning
		mock_log_obsolete.warning.assert_called_once()
		warning_call = mock_log_obsolete.warning.call_args
		self.assertIn('public_seacat_auth_base_url', warning_call[0][0])
		self.assertIn('auth_webui_api_base_url', warning_call[0][0])
		self.assertEqual(warning_call[1]['struct_data']['eol'], '2026-01-31')

	def test_validation_auth_webui_api_not_suburl_raises_error(self):
		"""Test that ValueError is raised when AuthWebUiApiBaseUrl is not a sub-URL of AuthWebUiUrl"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'https://example.com/different/path/',
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'https://example.com/auth/',
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		
		with self.assertRaises(ValueError) as context:
			app._prepare_public_urls()
		
		self.assertIn('auth_webui_api_base_url', str(context.exception))
		self.assertIn('not a sub-URL', str(context.exception))
		self.assertIn('auth_webui_base_url', str(context.exception))

	def test_validation_relative_urls_not_suburl_raises_error(self):
		"""Test validation with relative URLs that are not sub-URLs"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'api/seacat-auth/',  # Different base path
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'auth/',  # Base path is 'auth/'
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		
		with self.assertRaises(ValueError) as context:
			app._prepare_public_urls()
		
		self.assertIn('not a sub-URL', str(context.exception))

	def test_complex_nested_path(self):
		"""Test with complex nested path structure"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'auth/v2/api/seacat-auth/',
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'auth/',
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		self.assertEqual(app.AuthWebUiApiBaseUrl, 'https://example.com/auth/v2/api/seacat-auth/')
		self.assertEqual(app.AuthWebUiUrl, 'https://example.com/auth/')
		self.assertTrue(app.AuthWebUiApiBaseUrl.startswith(app.AuthWebUiUrl))

	def test_http_scheme_both_urls(self):
		"""Test with HTTP scheme (insecure)"""
		config_values = {
			('general', 'public_url'): 'http://localhost/',
			('general', 'auth_webui_api_base_url'): 'auth/api/seacat-auth/',
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'auth/',
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		self.assertEqual(app.AuthWebUiApiBaseUrl, 'http://localhost/auth/api/seacat-auth/')
		self.assertEqual(app.AuthWebUiUrl, 'http://localhost/auth/')
		self.assertTrue(app.AuthWebUiApiBaseUrl.startswith(app.AuthWebUiUrl))

	def test_mixed_absolute_relative_urls(self):
		"""Test with mixed absolute and relative URL configurations"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'auth/api/seacat-auth/',  # Relative
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'https://example.com/auth/',  # Absolute
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		# Relative URL should be resolved against PublicUrl
		self.assertEqual(app.AuthWebUiApiBaseUrl, 'https://example.com/auth/api/seacat-auth/')
		self.assertEqual(app.AuthWebUiUrl, 'https://example.com/auth/')

	def test_public_url_from_environment_variable(self):
		"""Test PublicUrl fallback to environment variable"""
		config_values = {
			('general', 'public_url'): '',  # Empty, should use env var
			('general', 'auth_webui_api_base_url'): 'auth/api/seacat-auth/',
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'auth/',
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		with patch.dict(os.environ, {'PUBLIC_URL': 'https://env-example.com'}):
			app, _ = self._create_mock_app(config_values)
			app._prepare_public_urls()
			
			self.assertEqual(app.PublicUrl, 'https://env-example.com/')
			self.assertEqual(app.AuthWebUiApiBaseUrl, 'https://env-example.com/auth/api/seacat-auth/')

	def test_edge_case_same_url_for_both(self):
		"""Test edge case where both URLs are the same (minimal sub-path)"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'https://example.com/auth/',
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'https://example.com/auth/',
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		# Should be valid since API URL starts with (equals) WebUI URL
		self.assertEqual(app.AuthWebUiApiBaseUrl, 'https://example.com/auth/')
		self.assertEqual(app.AuthWebUiUrl, 'https://example.com/auth/')
		self.assertTrue(app.AuthWebUiApiBaseUrl.startswith(app.AuthWebUiUrl))

	def test_url_resolution_preserves_domain(self):
		"""Test that URL resolution preserves domain correctly"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'auth/api/seacat-auth/',
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'auth/',
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		# Parse URLs to verify structure
		auth_api_parsed = urllib.parse.urlparse(app.AuthWebUiApiBaseUrl)
		webui_parsed = urllib.parse.urlparse(app.AuthWebUiUrl)
		
		self.assertEqual(auth_api_parsed.scheme, 'https')
		self.assertEqual(auth_api_parsed.netloc, 'example.com')
		self.assertEqual(auth_api_parsed.path, '/auth/api/seacat-auth/')
		
		self.assertEqual(webui_parsed.scheme, 'https')
		self.assertEqual(webui_parsed.netloc, 'example.com')
		self.assertEqual(webui_parsed.path, '/auth/')

	def test_backward_compat_with_absolute_url(self):
		"""Test backward compatibility with absolute URL in old config"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'auth/api/seacat-auth/',
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'auth/',
			('general', 'public_seacat_auth_base_url'): 'https://example.com/api/seacat-auth/',
		}
		
		app, mock_log_obsolete = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		# Should use old config value
		self.assertEqual(app.AuthWebUiApiBaseUrl, 'https://example.com/api/seacat-auth/')
		
		# Should still log warning
		mock_log_obsolete.warning.assert_called_once()

	def test_url_with_port_number(self):
		"""Test URL handling with explicit port number"""
		config_values = {
			('general', 'public_url'): 'https://example.com:8443/',
			('general', 'auth_webui_api_base_url'): 'auth/api/seacat-auth/',
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'auth/',
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		self.assertEqual(app.AuthWebUiApiBaseUrl, 'https://example.com:8443/auth/api/seacat-auth/')
		self.assertEqual(app.AuthWebUiUrl, 'https://example.com:8443/auth/')

	def test_validation_case_sensitive_paths(self):
		"""Test that path validation is case-sensitive"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'Auth/api/seacat-auth/',  # Capital A
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'auth/',  # Lowercase a
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		
		# Should raise error because 'Auth' != 'auth' (case sensitive)
		with self.assertRaises(ValueError) as context:
			app._prepare_public_urls()
		
		self.assertIn('not a sub-URL', str(context.exception))

	def test_multiple_trailing_slashes_normalized(self):
		"""Test that multiple trailing slashes are handled correctly"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'auth/api/seacat-auth///',  # Multiple slashes
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'auth/',
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		# rstrip('/') + '/' should result in single trailing slash
		self.assertTrue(app.AuthWebUiApiBaseUrl.endswith('/'))
		self.assertFalse(app.AuthWebUiApiBaseUrl.endswith('//'))

	def test_openidconnect_url_still_works(self):
		"""Test that OpenID Connect URL preparation still works correctly"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'auth/api/seacat-auth/',
			('general', 'public_openidconnect_base_url'): 'api/openidconnect/',
			('general', 'auth_webui_base_url'): 'auth/',
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		self.assertEqual(app.PublicOpenIdConnectApiUrl, 'https://example.com/api/openidconnect/')

	def test_no_backward_compat_value_uses_new_config(self):
		"""Test that when old config is None, new config is used"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'auth/api/seacat-auth/',
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'auth/',
			('general', 'public_seacat_auth_base_url'): None,  # Explicitly None
		}
		
		app, mock_log_obsolete = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		# Should use new config value
		self.assertEqual(app.AuthWebUiApiBaseUrl, 'https://example.com/auth/api/seacat-auth/')
		
		# Should not log warning
		mock_log_obsolete.warning.assert_not_called()

	def test_validation_with_query_parameters(self):
		"""Test that URLs with query parameters are handled correctly"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'auth/api/seacat-auth/?version=1',
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'auth/',
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		# Query parameters should be preserved
		self.assertIn('?version=1', app.AuthWebUiApiBaseUrl)
		# Should still pass validation (startswith checks the base path)
		self.assertTrue(app.AuthWebUiApiBaseUrl.startswith(app.AuthWebUiUrl.split('?')[0]))

	def test_subdomain_difference_fails_validation(self):
		"""Test that different subdomains fail validation"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'https://api.example.com/seacat-auth/',
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'https://example.com/auth/',
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		
		with self.assertRaises(ValueError) as context:
			app._prepare_public_urls()
		
		self.assertIn('not a sub-URL', str(context.exception))

	def test_empty_path_segments(self):
		"""Test handling of empty path segments in URLs"""
		config_values = {
			('general', 'public_url'): 'https://example.com/',
			('general', 'auth_webui_api_base_url'): 'auth//api//seacat-auth/',
			('general', 'public_openidconnect_base_url'): 'api/',
			('general', 'auth_webui_base_url'): 'auth/',
			('general', 'public_seacat_auth_base_url'): None,
		}
		
		app, _ = self._create_mock_app(config_values)
		app._prepare_public_urls()
		
		# urllib.parse.urljoin normalizes paths
		self.assertTrue(app.AuthWebUiApiBaseUrl.startswith(app.AuthWebUiUrl))


class ExternalLoginServiceUrlUsageTestCase(unittest.TestCase):
	"""
	Test suite for ExternalAuthenticationService URL usage.
	Tests that the service correctly uses AuthWebUiApiBaseUrl.
	"""

	def test_callback_url_template_uses_auth_webui_api_base_url(self):
		"""Test that callback URL template uses AuthWebUiApiBaseUrl"""
		from unittest.mock import MagicMock
		
		# Create mock app with the new attribute
		mock_app = MagicMock()
		mock_app.AuthWebUiApiBaseUrl = 'https://example.com/auth/api/seacat-auth/'
		mock_app.PublicUrl = 'https://example.com/'
		mock_app.get_service = MagicMock()
		mock_app.PubSub = MagicMock()
		
		# Mock config
		with patch('asab.Config') as mock_config:
			mock_config.getint.return_value = 32
			mock_config.getseconds.return_value = 600
			mock_config.get.return_value = 'https://example.com/'
			mock_config.sections.return_value = []
			
			from seacatauth.external_login.authentication.service import ExternalAuthenticationService
			service = ExternalAuthenticationService(mock_app)
			
			# Verify CallbackUrlTemplate uses AuthWebUiApiBaseUrl
			expected_url = 'https://example.com/auth/api/seacat-auth/public/ext-login/callback'
			self.assertEqual(service.CallbackUrlTemplate, expected_url)
			
			# Verify it starts with AuthWebUiApiBaseUrl
			self.assertTrue(service.CallbackUrlTemplate.startswith(
				mock_app.AuthWebUiApiBaseUrl.rstrip('/')
			))


class FeatureServiceUrlUsageTestCase(unittest.TestCase):
	"""
	Test suite for FeatureService URL usage.
	Tests that the service correctly uses AuthWebUiApiBaseUrl in feature endpoints.
	"""

	def setUp(self):
		"""Set up test fixtures"""
		self.mock_app = MagicMock()
		self.mock_app.AuthWebUiApiBaseUrl = 'https://example.com/auth/api/seacat-auth/'
		self.mock_app.get_service = MagicMock()
		
		# Mock external authentication service with providers
		self.mock_ext_auth_service = MagicMock()
		self.mock_provider = MagicMock()
		self.mock_provider.Type = 'google'
		self.mock_provider.Label = 'Google'
		self.mock_ext_auth_service.Providers = {'google': self.mock_provider}
		
		self.mock_app.get_service.return_value = self.mock_ext_auth_service

	def test_login_uri_uses_auth_webui_api_base_url(self):
		"""Test that external login URIs use AuthWebUiApiBaseUrl"""
		from seacatauth.feature.service import FeatureService
		
		service = FeatureService(self.mock_app)
		service.AuthenticationService = MagicMock()
		service.CredentialsService = MagicMock()
		service.ExternalAuthenticationService = self.mock_ext_auth_service
		
		# Get features
		import asyncio
		features = asyncio.run(service.get_features())
		
		# Check login URI
		self.assertIn('login', features)
		self.assertIn('external', features['login'])
		
		login_uri = features['login']['external'][0]['authorize_uri']
		expected_uri = 'https://example.com/auth/api/seacat-auth/public/ext-login/google/login'
		self.assertEqual(login_uri, expected_uri)
		
		# Verify it starts with AuthWebUiApiBaseUrl
		self.assertTrue(login_uri.startswith(
			self.mock_app.AuthWebUiApiBaseUrl.rstrip('/')
		))

	def test_pair_uri_uses_auth_webui_api_base_url(self):
		"""Test that external account pairing URIs use AuthWebUiApiBaseUrl"""
		from seacatauth.feature.service import FeatureService
		
		service = FeatureService(self.mock_app)
		service.AuthenticationService = MagicMock()
		service.CredentialsService = MagicMock()
		service.ExternalAuthenticationService = self.mock_ext_auth_service
		
		# Get features
		import asyncio
		features = asyncio.run(service.get_features())
		
		# Check pairing URI
		self.assertIn('my_account', features)
		self.assertIn('external_login', features['my_account'])
		
		pair_uri = features['my_account']['external_login'][0]['authorize_uri']
		expected_uri = 'https://example.com/auth/api/seacat-auth/public/ext-login/google/pair'
		self.assertEqual(pair_uri, expected_uri)
		
		# Verify it starts with AuthWebUiApiBaseUrl
		self.assertTrue(pair_uri.startswith(
			self.mock_app.AuthWebUiApiBaseUrl.rstrip('/')
		))

	def test_multiple_providers_all_use_correct_base_url(self):
		"""Test that all provider URIs use the correct base URL"""
		# Add multiple providers
		mock_provider_fb = MagicMock()
		mock_provider_fb.Type = 'facebook'
		mock_provider_fb.Label = 'Facebook'
		
		self.mock_ext_auth_service.Providers = {
			'google': self.mock_provider,
			'facebook': mock_provider_fb
		}
		
		from seacatauth.feature.service import FeatureService
		
		service = FeatureService(self.mock_app)
		service.AuthenticationService = MagicMock()
		service.CredentialsService = MagicMock()
		service.ExternalAuthenticationService = self.mock_ext_auth_service
		
		# Get features
		import asyncio
		features = asyncio.run(service.get_features())
		
		# Check that all URIs start with the correct base URL
		for provider_config in features['login']['external']:
			self.assertTrue(provider_config['authorize_uri'].startswith(
				self.mock_app.AuthWebUiApiBaseUrl.rstrip('/')
			))
		
		for provider_config in features['my_account']['external_login']:
			self.assertTrue(provider_config['authorize_uri'].startswith(
				self.mock_app.AuthWebUiApiBaseUrl.rstrip('/')
			))

	def test_uri_format_correctness(self):
		"""Test that URIs are correctly formatted with provider type"""
		from seacatauth.feature.service import FeatureService
		
		service = FeatureService(self.mock_app)
		service.AuthenticationService = MagicMock()
		service.CredentialsService = MagicMock()
		service.ExternalAuthenticationService = self.mock_ext_auth_service
		
		# Get features
		import asyncio
		features = asyncio.run(service.get_features())
		
		# Check URI structure
		login_uri = features['login']['external'][0]['authorize_uri']
		pair_uri = features['my_account']['external_login'][0]['authorize_uri']
		
		# Should have correct path structure
		self.assertIn('/public/ext-login/google/login', login_uri)
		self.assertIn('/public/ext-login/google/pair', pair_uri)
		
		# Should not have double slashes
		self.assertNotIn('//', login_uri.replace('https://', ''))
		self.assertNotIn('//', pair_uri.replace('https://', ''))