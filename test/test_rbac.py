import unittest

from seacatauth.authz import RBACService
from seacatauth.exceptions import TenantRequired


class RBACTestCase(unittest.TestCase):
	maxDiff = None

	authz_test_data = {
		"*": ["post:read", "post:write", "post:edit"],
		"first-tenant": ["post:read", "post:write", "post:edit", "authz:tenant:admin"],
	}

	notenant_authz_test_data = {
		"*": ["post:read", "post:write", "post:edit"],
	}

	superuser_authz_test_data = {
		"*": ["post:read", "authz:superuser"],
	}

	def test_tenant_access(self):
		"""
		Check if the user has access to specified tenant
		"""

		access = RBACService.has_resource_access(self.authz_test_data, "first-tenant", ["tenant:access"])
		self.assertTrue(access)

		access = RBACService.has_resource_access(self.authz_test_data, "second-tenant", ["tenant:access"])
		self.assertFalse(access)

		self.assertRaises(
			TenantRequired,
			RBACService.has_resource_access(self.authz_test_data, None, ["tenant:access"])
		)

		# Check superuser
		access = RBACService.has_resource_access(self.superuser_authz_test_data, "first-tenant", ["tenant:access"])
		self.assertTrue(access)


	def test_tenant_access_softcheck(self):
		"""
		Check if the user has access to ANY tenant
		"""
		access = RBACService.has_resource_access(self.authz_test_data, "*", ["tenant:access"])
		self.assertTrue(access)

		access = RBACService.has_resource_access(self.notenant_authz_test_data, "*", ["tenant:access"])
		self.assertFalse(access)

		# Check superuser
		access = RBACService.has_resource_access(self.superuser_authz_test_data, "*", ["tenant:access"])
		self.assertTrue(access)


	def test_tenant_resource(self):
		"""
		Check if the user has access to a specified resource under a specified tenant
		"""

		access = RBACService.has_resource_access(
			self.authz_test_data,
			"first-tenant",
			["authz:tenant:admin"]
		)
		self.assertTrue(access)

		access = RBACService.has_resource_access(
			self.authz_test_data,
			"first-tenant",
			["post:delete"]
		)
		self.assertFalse(access)

		access = RBACService.has_resource_access(
			self.authz_test_data,
			"second-tenant",
			["post:edit"]
		)
		self.assertFalse(access)

		# Check superuser
		access = RBACService.has_resource_access(self.superuser_authz_test_data, "first-tenant", ["post:edit"])
		self.assertTrue(access)


	def test_tenant_multiple_resource(self):
		"""
		Check if the user has access to ALL the specified resources under a specified tenant
		"""

		access = RBACService.has_resource_access(
			self.authz_test_data,
			"first-tenant",
			["post:edit", "post:read"]
		)
		self.assertTrue(access)

		access = RBACService.has_resource_access(
			self.authz_test_data,
			"first-tenant",
			["post:edit", "post:delete"]
		)
		self.assertFalse(access)

		# Check superuser
		access = RBACService.has_resource_access(
			self.superuser_authz_test_data, "first-tenant", ["post:edit", "post:delete"]
		)
		self.assertTrue(access)


	def test_resource_softcheck(self):
		"""
		Check if the user has access to a specified resource under ANY tenant
		"""

		access = RBACService.has_resource_access(
			self.authz_test_data,
			"*",
			["authz:tenant:admin"]
		)
		self.assertTrue(access)

		access = RBACService.has_resource_access(
			self.authz_test_data,
			"*",
			["post:delete"]
		)
		self.assertFalse(access)

		# Check superuser
		access = RBACService.has_resource_access(self.superuser_authz_test_data, "*", ["post:edit"])
		self.assertTrue(access)


	def test_multiple_resource_softcheck(self):
		"""
		Check if the user has access to ALL the specified resources under ANY tenant
		"""

		access = RBACService.has_resource_access(
			self.authz_test_data,
			"*",
			["authz:tenant:admin", "post:edit"]
		)
		self.assertTrue(access)

		access = RBACService.has_resource_access(
			self.authz_test_data,
			"*",
			["authz:tenant:admin", "post:delete"]
		)
		self.assertFalse(access)

		# Check superuser
		access = RBACService.has_resource_access(
			self.superuser_authz_test_data, "*", ["authz:tenant:admin", "post:edit"]
		)
		self.assertTrue(access)


	def test_global_roles_resource(self):
		"""
		Check if the user has access to a specified resource via their global roles
		"""

		access = RBACService.has_resource_access(
			self.authz_test_data,
			None,
			["post:read"]
		)
		self.assertTrue(access)

		access = RBACService.has_resource_access(
			self.authz_test_data,
			None,
			["authz:tenant:admin"]
		)
		self.assertFalse(access)

		# Check superuser
		access = RBACService.has_resource_access(self.superuser_authz_test_data, None, ["post:edit"])
		self.assertTrue(access)


	def test_global_roles_multiple_resources(self):
		"""
		Check if the user has access to ALL the specified resources via global roles
		"""

		access = RBACService.has_resource_access(
			self.authz_test_data,
			None,
			["post:read", "post:edit"]
		)
		self.assertTrue(access)

		access = RBACService.has_resource_access(
			self.authz_test_data,
			None,
			["post:write", "authz:tenant:admin"]
		)
		self.assertFalse(access)

		# Check superuser
		access = RBACService.has_resource_access(self.superuser_authz_test_data, None, ["authz:tenant:admin", "post:edit"])
		self.assertTrue(access)


	def test_superuser(self):
		"""
		Check if the user has access to the authz:superuser resource
		"""

		access = RBACService.has_resource_access(
			self.authz_test_data,
			"first-tenant",
			["authz:superuser"]
		)
		self.assertFalse(access)

		access = RBACService.has_resource_access(
			self.authz_test_data,
			"*",
			["authz:superuser"]
		)
		self.assertFalse(access)

		access = RBACService.has_resource_access(
			self.authz_test_data,
			None,
			["authz:superuser"]
		)
		self.assertFalse(access)

		# Check superuser
		access = RBACService.has_resource_access(
			self.superuser_authz_test_data,
			"first-tenant",
			["authz:superuser"]
		)
		self.assertTrue(access)

		access = RBACService.has_resource_access(
			self.superuser_authz_test_data,
			"*",
			["authz:superuser"]
		)
		self.assertTrue(access)

		access = RBACService.has_resource_access(
			self.superuser_authz_test_data,
			None,
			["authz:superuser"]
		)
		self.assertTrue(access)
