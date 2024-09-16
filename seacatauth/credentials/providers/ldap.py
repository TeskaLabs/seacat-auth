import logging
import base64
import datetime
import contextlib

from typing import Optional


import ldap
import ldap.resiter
import ldap.filter

import asab
import asab.proactor

from .abc import CredentialsProviderABC

#

L = logging.getLogger(__name__)

#


_TLS_VERSION = {
	"1.0": ldap.OPT_X_TLS_PROTOCOL_TLS1_0,
	"1.1": ldap.OPT_X_TLS_PROTOCOL_TLS1_1,
	"1.2": ldap.OPT_X_TLS_PROTOCOL_TLS1_2,
	"1.3": ldap.OPT_X_TLS_PROTOCOL_TLS1_3,
}


class LDAPObject(ldap.ldapobject.LDAPObject, ldap.resiter.ResultProcessor):
	pass


class LDAPCredentialsService(asab.Service):

	def __init__(self, app, service_name="seacatauth.credentials.ldap"):
		super().__init__(app, service_name)
		app.add_module(asab.proactor.Module)


	def create_provider(self, provider_id, config_section_name):
		proactor_svc = self.App.get_service("asab.ProactorService")
		return LDAPCredentialsProvider(provider_id, config_section_name, proactor_svc)


class LDAPCredentialsProvider(CredentialsProviderABC):

	Type = "ldap"

	ConfigDefaults = {
		"uri": "ldap://localhost:389/",  # Multiple URIs need to be separated by comma or whitespace
		"network_timeout": "10",  # set network_timeout to -1 for no timeout
		"username": "cn=admin,dc=example,dc=org",
		"password": "admin",
		"base": "dc=example,dc=org",
		"filter": "(&(objectClass=inetOrgPerson)(cn=*))",  # should filter valid users only
		"attributes": "mail mobile",

		# Path to CA file in PEM format
		"tls_cafile": "",

		# Certificate policy.
		# Possible options (from python-ldap docs):
		# "never"  - Don’t check server cert and host name
		# "allow"  - Used internally by slapd server.
		# "demand" - Validate peer cert chain and host name
		# "hard"   - Same as "demand"
		"tls_require_cert": "never",

		"tls_protocol_min": "",
		"tls_protocol_max": "",
		"tls_cipher_suite": "",

		"attrusername": "cn",  # LDAP attribute that should be used as a username, e.g. `uid` or `sAMAccountName`
	}


	def __init__(self, provider_id, config_section_name, proactor_svc):
		super().__init__(provider_id, config_section_name)

		# This provider is heavilly using proactor design pattern to allow
		# synchronous library (python-ldap) to be used from asynchronous code
		self.ProactorService = proactor_svc

		attr = set(self.Config["attributes"].split(" "))
		attr.add("createTimestamp")
		attr.add("modifyTimestamp")
		attr.add("cn")
		attr.add(self.Config["attrusername"])
		self.AttrList = list(attr)

		# Fields to filter by when locating a user
		self._locate_filter_fields = ["cn", "mail", "mobile"]
		# If attrusername field is not empty, locate by it too
		if len(self.Config["attrusername"]) > 0:
			self._locate_filter_fields.append(self.Config["attrusername"])


	async def get_login_descriptors(self, credentials_id):
		return [{
			"id": "default",
			"label": "Use recommended login.",
			"factors": [{
				"id": "password",
				"type": "password"
			}],
		}]


	@contextlib.contextmanager
	def _ldap_client(self):
		ldap_client = LDAPObject(self.Config["uri"])
		ldap_client.protocol_version = ldap.VERSION3
		ldap_client.set_option(ldap.OPT_REFERRALS, 0)

		network_timeout = int(self.Config.get("network_timeout"))
		ldap_client.set_option(ldap.OPT_NETWORK_TIMEOUT, network_timeout)

		# Enable TLS
		if self.Config["uri"].startswith("ldaps"):
			self._enable_tls(ldap_client)

		ldap_client.simple_bind_s(self.Config["username"], self.Config["password"])

		try:
			yield ldap_client

		finally:
			ldap_client.unbind_s()

	def _enable_tls(self, ldap_client):
		tls_cafile = self.Config["tls_cafile"]

		# Add certificate authority
		if len(tls_cafile) > 0:
			ldap_client.set_option(ldap.OPT_X_TLS_CACERTFILE, tls_cafile)

		# Set cert policy
		if self.Config["tls_require_cert"] == "never":
			ldap_client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
		elif self.Config["tls_require_cert"] == "demand":
			ldap_client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
		elif self.Config["tls_require_cert"] == "allow":
			ldap_client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
		elif self.Config["tls_require_cert"] == "hard":
			ldap_client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_HARD)
		else:
			L.error("Invalid 'tls_require_cert' value: {!r}. Defaulting to 'demand'.".format(
				self.Config["tls_require_cert"]
			))
			ldap_client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)

		# Misc TLS options
		tls_protocol_min = self.Config["tls_protocol_min"]
		if tls_protocol_min != "":
			if tls_protocol_min not in _TLS_VERSION:
				raise ValueError("'tls_protocol_min' must be one of {} or empty.".format(list(_TLS_VERSION)))
			ldap_client.set_option(ldap.OPT_X_TLS_PROTOCOL_MIN, _TLS_VERSION[tls_protocol_min])

		tls_protocol_max = self.Config["tls_protocol_max"]
		if tls_protocol_max != "":
			if tls_protocol_max not in _TLS_VERSION:
				raise ValueError("'tls_protocol_max' must be one of {} or empty.".format(list(_TLS_VERSION)))
			ldap_client.set_option(ldap.OPT_X_TLS_PROTOCOL_MAX, _TLS_VERSION[tls_protocol_max])

		if self.Config["tls_cipher_suite"] != "":
			ldap_client.set_option(ldap.OPT_X_TLS_CIPHER_SUITE, self.Config["tls_cipher_suite"])

		# NEWCTX needs to be the last option, because it applies all the prepared options to the new context
		ldap_client.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

	def _get_worker(self, prefix, credentials_id, include=None) -> Optional[dict]:

		# TODO: Validate credetials_id with regex

		cn = base64.urlsafe_b64decode(credentials_id[len(prefix):]).decode("utf-8")
		with self._ldap_client() as lc:
			try:
				sr = lc.search_s(
					cn,
					ldap.SCOPE_BASE,
					filterstr=self.Config["filter"],
					attrlist=self.AttrList,
				)
			except ldap.NO_SUCH_OBJECT as e:
				L.error(e)
				sr = []

		if len(sr) == 0:
			raise KeyError("Credentials {!r} not found".format(credentials_id))

		assert len(sr) == 1
		dn, entry = sr[0]

		return _normalize_entry(
			prefix,
			self.Type,
			self.ProviderID,
			dn,
			entry,
			self.Config["attrusername"]
		)


	async def get(self, credentials_id, include=None) -> Optional[dict]:
		prefix = "{}:{}:".format(self.Type, self.ProviderID)
		if not credentials_id.startswith(prefix):
			raise KeyError("Credentials {!r} not found".format(credentials_id))

		return await self.ProactorService.execute(self._get_worker, prefix, credentials_id, include)


	def _count_worker(self, filterstr):
		count = 0
		with self._ldap_client() as lc:
			msgid = lc.search(
				self.Config["base"],
				ldap.SCOPE_SUBTREE,
				filterstr=filterstr,
				attrsonly=1,  # If attrsonly is non-zero
				attrlist=["cn", "mail", "mobile"],  # For counting, we need only absolutely minimum set of attributes
			)
			result_iter = lc.allresults(msgid)

			for res_type, res_data, res_msgid, res_controls in result_iter:
				for dn, entry in res_data:
					if dn is None:
						continue
					else:
						count += 1

		return count


	async def count(self, filtr=None) -> int:
		filterstr = self._build_search_filter(filtr)
		return await self.ProactorService.execute(self._count_worker, filterstr)


	def _search_worker(self, filterstr):

		# TODO: sorting
		prefix = "{}:{}:".format(self.Type, self.ProviderID)
		result = []

		with self._ldap_client() as lc:
			msgid = lc.search(
				self.Config["base"],
				ldap.SCOPE_SUBTREE,
				filterstr=filterstr,
				attrlist=self.AttrList,
			)
			result_iter = lc.allresults(msgid)

			for res_type, res_data, res_msgid, res_controls in result_iter:
				for dn, entry in res_data:
					if dn is not None:
						result.append(_normalize_entry(
							prefix,
							self.Type,
							self.ProviderID,
							dn,
							entry,
							self.Config["attrusername"]
						))

		return result


	async def search(self, filter: dict = None, **kwargs) -> list:
		# TODO: Implement filtering and pagination
		if filter is not None:
			return []
		filterstr = self.Config["filter"]
		return await self.ProactorService.execute(self._search_worker, filterstr)


	async def iterate(self, offset: int = 0, limit: int = -1, filtr: str = None):
		filterstr = self._build_search_filter(filtr)
		arr = await self.ProactorService.execute(self._search_worker, filterstr)
		for i in arr[offset:None if limit == -1 else limit + offset]:
			yield i

	def _build_search_filter(self, filtr=None):
		if not filtr:
			filterstr = self.Config["filter"]
		else:
			# The query filter is the intersection of the filter from config
			# and the filter defined by the search request
			# The username must START WITH the given filter string
			filter_template = "(&{}({}=*%s*))".format(self.Config["filter"], self.Config["attrusername"])
			assertion_values = ["{}".format(filtr.lower())]
			filterstr = ldap.filter.filter_format(
				filter_template=filter_template,
				assertion_values=assertion_values
			)
		return filterstr

	def _locate_worker(self, ident: str):
		with self._ldap_client() as lc:

			# Build the filter template
			# Example: (|(cn=%s)(mail=%s)(mobile=%s)(sAMAccountName=%s))
			filter_template = "(|{})".format(
				"".join("({}=%s)".format(field) for field in self._locate_filter_fields)
			)
			assertion_values = tuple(
				ident for _ in self._locate_filter_fields
			)

			msgid = lc.search(
				self.Config["base"],
				ldap.SCOPE_SUBTREE,
				filterstr=ldap.filter.filter_format(
					filter_template=filter_template,
					assertion_values=assertion_values
				),
				attrlist=["cn"]
			)
			result_iter = lc.allresults(msgid)
			for res_type, res_data, res_msgid, res_controls in result_iter:
				for dn, entry in res_data:
					if dn is not None:
						return "{}:{}:{}".format(
							self.Type,
							self.ProviderID,
							base64.urlsafe_b64encode(dn.encode("utf-8")).decode("ascii"),
						)

		return None


	async def locate(self, ident: str, ident_fields: dict = None, login_dict: dict = None) -> str:
		# TODO: Implement ident_fields support
		"""
		Locate search for the exact match of provided ident and the username in the htpasswd file
		"""
		return await self.ProactorService.execute(self._locate_worker, ident)


	def _authenticate_worker(self, credentials_id: str, credentials: dict) -> bool:
		prefix = "{}:{}:".format(self.Type, self.ProviderID)

		password = credentials.get("password")
		dn = base64.urlsafe_b64decode(credentials_id[len(prefix):]).decode("utf-8")

		lc = LDAPObject(self.Config["uri"])
		lc.protocol_version = ldap.VERSION3
		lc.set_option(ldap.OPT_REFERRALS, 0)

		# Enable TLS
		if self.Config["uri"].startswith("ldaps"):
			self._enable_tls(lc)

		try:
			lc.simple_bind_s(dn, password)
		except ldap.INVALID_CREDENTIALS:
			L.log(asab.LOG_NOTICE, "Authentication failed: Invalid LDAP credentials.", struct_data={
				"cid": credentials_id, "dn": dn})
			return False

		lc.unbind_s()

		return True


	async def authenticate(self, credentials_id: str, credentials: dict) -> bool:
		return await self.ProactorService.execute(self._authenticate_worker, credentials_id, credentials)


def _normalize_entry(prefix, ptype, provider_id, dn, entry, attrusername: str = "cn"):
	ret = {
		"_id": prefix + base64.urlsafe_b64encode(dn.encode("utf-8")).decode("ascii"),
		"_type": ptype,
		"_provider_id": provider_id,
	}

	ldap_obj = {
		"dn": dn,
	}
	for k, v in entry.items():
		if k in frozenset(["userPassword"]):
			continue
		if isinstance(v, list):
			if len(v) == 1:
				v = v[0].decode("utf-8")
			else:
				v = [i.decode("utf-8") for i in v]
		ldap_obj[k] = v

	v = ldap_obj.pop(attrusername, None)
	if v is not None:
		ret["username"] = v
	else:
		# This is fallback, since we need a username on various places
		ret["username"] = dn

	v = ldap_obj.pop("cn", None)
	if v is not None:
		ret["full_name"] = v

	v = ldap_obj.pop("mail", None)
	if v is not None:
		ret["email"] = v

	v = ldap_obj.pop("mobile", None)
	if v is not None:
		ret["phone"] = v

	v = ldap_obj.pop("userAccountControl", None)
	if v is not None:
		# userAccountControl is an array of binary flags returned as a decimal integer
		# byte #1 is ACCOUNTDISABLE which corresponds to "suspended" status
		# https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
		try:
			ret["suspended"] = int(v) & 2 == 2
		except ValueError:
			pass

	v = ldap_obj.pop("createTimestamp", None)
	if v is not None:
		ret["_c"] = _parse_timestamp(v)
	else:
		v = ldap_obj.pop("createTimeStamp", None)
		if v is not None:
			ret["_c"] = _parse_timestamp(v)

	v = ldap_obj.pop("modifyTimestamp", None)
	if v is not None:
		ret["_m"] = _parse_timestamp(v)
	else:
		v = ldap_obj.pop("modifyTimeStamp", None)
		if v is not None:
			ret["_m"] = _parse_timestamp(v)

	if len(ldap_obj) > 0:
		ret["_ldap"] = ldap_obj

	return ret


def _parse_timestamp(ts: str) -> datetime.datetime:
	try:
		return datetime.datetime.strptime(ts, r"%Y%m%d%H%M%SZ")
	except ValueError:
		pass

	return datetime.datetime.strptime(ts, r"%Y%m%d%H%M%S.%fZ")
