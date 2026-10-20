import unittest
from unittest.mock import call, patch

from seacatauth.credentials.service import audit_log_credentials_update


class CredentialsUpdateAuditTestCase(unittest.TestCase):

	@patch("seacatauth.credentials.service.AuditLogger.notice")
	def test_suspend_logs_explicit_message_with_cid(self, notice):
		audit_log_credentials_update("mongodb:user-1", {"suspended": True})

		notice.assert_called_once_with(
			"Credentials suspended",
			struct_data={"cid": "mongodb:user-1", "suspended": True},
		)

	@patch("seacatauth.credentials.service.AuditLogger.notice")
	def test_activate_logs_explicit_message_with_cid(self, notice):
		audit_log_credentials_update("mongodb:user-1", {"suspended": False})

		notice.assert_called_once_with(
			"Credentials activated",
			struct_data={"cid": "mongodb:user-1", "suspended": False},
		)

	@patch("seacatauth.credentials.service.AuditLogger.notice")
	def test_one_log_line_per_attribute(self, notice):
		audit_log_credentials_update(
			"mongodb:user-1",
			{"email": "a@example.com", "phone": "+420123456789"},
		)

		self.assertEqual(notice.call_count, 2)
		notice.assert_has_calls([
			call(
				"Credentials 'email' updated",
				struct_data={"cid": "mongodb:user-1", "attribute": "email"},
			),
			call(
				"Credentials 'phone' updated",
				struct_data={"cid": "mongodb:user-1", "attribute": "phone"},
			),
		])

	@patch("seacatauth.credentials.service.AuditLogger.notice")
	def test_mixed_attribute_and_suspend_update(self, notice):
		audit_log_credentials_update(
			"mongodb:user-1",
			{"email": "a@example.com", "suspended": True},
		)

		self.assertEqual(notice.call_count, 2)
		notice.assert_has_calls([
			call(
				"Credentials 'email' updated",
				struct_data={"cid": "mongodb:user-1", "attribute": "email"},
			),
			call(
				"Credentials suspended",
				struct_data={"cid": "mongodb:user-1", "suspended": True},
			),
		])
