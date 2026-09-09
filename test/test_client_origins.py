import asyncio
import unittest
from unittest.mock import MagicMock

from seacatauth.client.service import ClientService, origin_from_redirect_uri
from seacatauth.models.const import OAuth2


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


class IsOriginAllowedTestCase(unittest.TestCase):

	def test_schedules_scan_and_raises_when_uninitialized(self):
		svc = object.__new__(ClientService)
		svc.PublicClientOrigins = None
		svc.TaskService = MagicMock()
		svc._schedule_public_client_origins_refresh = MagicMock()

		with self.assertRaises(RuntimeError):
			svc.is_origin_allowed("https://app.example")
		svc._schedule_public_client_origins_refresh.assert_called_once()

	def test_membership_when_initialized(self):
		svc = object.__new__(ClientService)
		svc.PublicClientOrigins = frozenset({"https://app.example"})
		svc._schedule_public_client_origins_refresh = MagicMock()

		self.assertTrue(svc.is_origin_allowed("https://app.example"))
		self.assertFalse(svc.is_origin_allowed("https://other.example"))
		svc._schedule_public_client_origins_refresh.assert_not_called()


class PublicClientOriginsRefreshTestCase(unittest.IsolatedAsyncioTestCase):

	async def test_initial_scan_concurrent_with_client_change(self):
		"""
		A slow startup scan must not overwrite a newer refresh triggered by a
		client change mid-flight; the final cache reflects the change.
		"""
		svc = object.__new__(ClientService)
		svc.PublicClientOrigins = None
		svc._PublicClientOriginsRefreshLock = asyncio.Lock()
		svc._PublicClientOriginsRefreshPending = False

		scan_started = asyncio.Event()
		allow_first_scan_finish = asyncio.Event()
		clients = [
			{
				"token_endpoint_auth_method": OAuth2.TokenEndpointAuthMethod.NONE,
				"redirect_uris": ["https://old.example/callback"],
			}
		]
		scan_count = 0

		async def iterate_clients():
			nonlocal scan_count
			scan_count += 1
			# Snapshot the client list for this scan (stale scans keep the old view).
			snapshot = list(clients)
			if scan_count == 1:
				scan_started.set()
				await allow_first_scan_finish.wait()
			for client in snapshot:
				yield client

		svc.iterate_clients = iterate_clients

		startup = asyncio.create_task(svc._refresh_public_client_origins())
		await scan_started.wait()
		self.assertIsNone(svc.PublicClientOrigins)

		# Client change while the initial scan is still in progress.
		clients[:] = [
			{
				"token_endpoint_auth_method": OAuth2.TokenEndpointAuthMethod.NONE,
				"redirect_uris": ["https://new.example/callback"],
			}
		]
		watcher = asyncio.create_task(svc._refresh_public_client_origins())
		# Wait until the watcher has marked a pending refresh and is blocked on the lock.
		for _ in range(100):
			if svc._PublicClientOriginsRefreshPending and svc._PublicClientOriginsRefreshLock.locked():
				break
			await asyncio.sleep(0)
		else:
			self.fail("Watcher did not coalesce behind the in-flight startup scan")

		allow_first_scan_finish.set()
		await asyncio.gather(startup, watcher)

		self.assertEqual(svc.PublicClientOrigins, frozenset({"https://new.example"}))
		self.assertGreaterEqual(scan_count, 2)
