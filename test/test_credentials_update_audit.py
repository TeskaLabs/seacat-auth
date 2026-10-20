import unittest
from unittest.mock import call, patch

from seacatauth.credentials.service import audit_log_credentials_update


class CredentialsUpdateAuditTestCase(unittest.TestCase):

	@patch("seacatauth.credentials.service.AuditLogger.notice")
	def test_suspend_logs_explicit_message_with_cid(self, notice):
		audit_log_credentials_update(
			"mongodb:user-1",
			{"suspended": True},
			{"suspended": False},
		)

		notice.assert_called_once_with(
			"Credentials suspended",
			struct_data={"cid": "mongodb:user-1", "suspended": True},
		)

	@patch("seacatauth.credentials.service.AuditLogger.notice")
	def test_activate_logs_explicit_message_with_cid(self, notice):
		audit_log_credentials_update(
			"mongodb:user-1",
			{"suspended": False},
			{"suspended": True},
		)

		notice.assert_called_once_with(
			"Credentials activated",
			struct_data={"cid": "mongodb:user-1", "suspended": False},
		)

	@patch("seacatauth.credentials.service.AuditLogger.notice")
	def test_one_log_line_per_attribute(self, notice):
		audit_log_credentials_update(
			"mongodb:user-1",
			{"email": "a@example.com", "phone": "+420123456789"},
			{"email": "old@example.com", "phone": "+420000000000"},
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
			{"email": "old@example.com", "suspended": False},
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

	@patch("seacatauth.credentials.service.AuditLogger.notice")
	def test_unchanged_attribute_is_not_logged(self, notice):
		audit_log_credentials_update(
			"mongodb:user-1",
			{"email": "a@example.com", "phone": "+420123456789"},
			{"email": "a@example.com", "phone": "+420000000000"},
		)

		notice.assert_called_once_with(
			"Credentials 'phone' updated",
			struct_data={"cid": "mongodb:user-1", "attribute": "phone"},
		)

	@patch("seacatauth.credentials.service.AuditLogger.notice")
	def test_unchanged_suspend_is_not_logged(self, notice):
		audit_log_credentials_update(
			"mongodb:user-1",
			{"suspended": True, "email": "a@example.com"},
			{"suspended": True, "email": "old@example.com"},
		)

		notice.assert_called_once_with(
			"Credentials 'email' updated",
			struct_data={"cid": "mongodb:user-1", "attribute": "email"},
		)

	@patch("seacatauth.credentials.service.AuditLogger.notice")
	def test_missing_suspended_treated_as_active(self, notice):
		# Credentials without "suspended" are active; setting suspended=False is no-op
		audit_log_credentials_update(
			"mongodb:user-1",
			{"suspended": False},
			{"email": "a@example.com"},
		)

		notice.assert_not_called()
