import binascii
import logging
import base64
import datetime
import contextlib
import typing


import ldap
import ldap.resiter
import ldap.filter
import asab
import asab.proactor
import asab.config

from .abc import CredentialsProviderABC
from ... import exceptions


L = logging.getLogger(__name__)


_TLS_VERSION = {
	"1.0": ldap.OPT_X_TLS_PROTOCOL_TLS1_0,
	"1.1": ldap.OPT_X_TLS_PROTOCOL_TLS1_1,
	"1.2": ldap.OPT_X_TLS_PROTOCOL_TLS1_2,
	"1.3": ldap.OPT_X_TLS_PROTOCOL_TLS1_3,
}


class LDAPCredentialsService(asab.Service):

	def __init__(self, app, service_name="seacatauth.credentials.ldap"):
		super().__init__(app, service_name)
		app.add_module(asab.proactor.Module)


	def create_provider(self, provider_id, config_section_name):
		proactor_svc = self.App.get_service("asab.ProactorService")
		return LDAPCredentialsProvider(self.App, provider_id, config_section_name, proactor_svc)


class LDAPCredentialsProvider(CredentialsProviderABC):

	Type = "ldap"

	ConfigDefaults = {
		"uri": "ldap://localhost:389/",  # Multiple URIs need to be separated by comma or whitespace
		"network_timeout": "10",  # set network_timeout to -1 for no timeout
		"username": "cn=admin,dc=example,dc=org",
		"password": "admin",
		"base": "dc=example,dc=org",
		"filter": "|(objectClass=organizationalPerson)(objectClass=inetOrgPerson)",
		"attributes": "mail mobile userAccountControl displayName",

		# Path to CA file in PEM format
		"tls_cafile": "",

		# Certificate policy.
		# Possible options (from python-ldap docs):
		# "never"  - Don’t check server cert and host name
		# "allow"  - Used internally by slapd server.
		# "demand" - Validate peer cert chain and host name
		# "hard"   - Same as "demand"
		"tls_require_cert": "never",

		# Path to client certificate and key files in PEM format
		"tls_certfile": "",
		"tls_keyfile": "",

		"tls_protocol_min": "",
		"tls_protocol_max": "",
		"tls_cipher_suite": "",

		"attrusername": "sAMAccountName",  # LDAP attribute that should be used as a username, e.g. `uid` or `sAMAccountName`
	}


	def __init__(self, app, provider_id, config_section_name, proactor_svc):
		super().__init__(app, provider_id, config_section_name)

		# This provider is heavilly using proactor design pattern to allow
		# synchronous library (python-ldap) to be used from asynchronous code
		self.ProactorService = proactor_svc

		self.LdapUri = self.Config["uri"]
		self.Base = self.Config["base"]
		self.Filter: str = self.Config["filter"]
		if not (self.Filter.startswith("(") and self.Filter.endswith(")")):
			self.Filter = "({})".format(self.Filter)
		self.AttrList = _prepare_attributes(self.Config)

		# Fields to filter by when locating a user
		self.IdentFields = ["mail", "mobile"]
		# If attrusername field is not empty, locate by it too
		if len(self.Config["attrusername"]) > 0:
			self.IdentFields.append(self.Config["attrusername"])


	async def get(
		self,
		credentials_id: str,
		include: typing.Optional[typing.Iterable[str]] = None
	) -> typing.Optional[dict]:
		try:
			cn = self._format_object_id(credentials_id)
		except ValueError:
			raise exceptions.CredentialsNotFoundError(credentials_id)

		try:
			return await self.ProactorService.execute(self._get_worker, cn)
		except KeyError as e:
			raise exceptions.CredentialsNotFoundError(credentials_id) from e
		except ldap.SERVER_DOWN:
			L.warning("LDAP server is down.", struct_data={"provider_id": self.ProviderID, "uri": self.LdapUri})
			raise exceptions.CredentialsNotFoundError(credentials_id)
		except ldap.INVALID_CREDENTIALS:
			L.error("Invalid LDAP credentials.", struct_data={"provider_id": self.ProviderID, "uri": self.LdapUri})
			raise exceptions.CredentialsNotFoundError(credentials_id)


	async def search(self, filter: dict = None, sort: dict = None, page: int = 0, limit: int = 0, **kwargs) -> list:
		# TODO: Implement pagination
		filterstr = self._build_search_filter(filter)
		try:
			return await self.ProactorService.execute(self._search_worker, filterstr)
		except ldap.SERVER_DOWN:
			L.warning("LDAP server is down.", struct_data={"provider_id": self.ProviderID, "uri": self.LdapUri})
			return []
		except ldap.INVALID_CREDENTIALS:
			L.error("Invalid LDAP credentials.", struct_data={"provider_id": self.ProviderID, "uri": self.LdapUri})
			return []


	async def count(self, filtr=None) -> int:
		filterstr = self._build_search_filter(filtr)
		try:
			return await self.ProactorService.execute(self._count_worker, filterstr)
		except ldap.SERVER_DOWN:
			L.warning("LDAP server is down.", struct_data={"provider_id": self.ProviderID, "uri": self.LdapUri})
			return None
		except ldap.INVALID_CREDENTIALS:
			L.error("Invalid LDAP credentials.", struct_data={"provider_id": self.ProviderID, "uri": self.LdapUri})
			return None


	async def iterate(self, offset: int = 0, limit: int = -1, filtr: str = None):
		filterstr = self._build_search_filter(filtr)
		try:
			results = await self.ProactorService.execute(self._search_worker, filterstr)
		except ldap.SERVER_DOWN:
			L.warning("LDAP server is down.", struct_data={"provider_id": self.ProviderID, "uri": self.LdapUri})
			return
		except ldap.INVALID_CREDENTIALS:
			L.error("Invalid LDAP credentials.", struct_data={"provider_id": self.ProviderID, "uri": self.LdapUri})
			return
		for i in results[offset:(None if limit == -1 else limit + offset)]:
			yield i


	async def locate(self, ident: str, ident_fields: dict = None, login_dict: dict = None) -> str:
		try:
			return await self.ProactorService.execute(self._locate_worker, ident, ident_fields)
		except ldap.SERVER_DOWN:
			L.warning("LDAP server is down.", struct_data={"provider_id": self.ProviderID, "uri": self.LdapUri})
			return None
		except ldap.INVALID_CREDENTIALS:
			L.error("Invalid LDAP credentials.", struct_data={"provider_id": self.ProviderID, "uri": self.LdapUri})
			return None


	async def authenticate(self, credentials_id: str, credentials: dict) -> bool:
		try:
			cn = self._format_object_id(credentials_id)
		except ValueError:
			return False

		password = credentials.get("password")
		try:
			return await self.ProactorService.execute(self._authenticate_worker, cn, password)
		except ldap.SERVER_DOWN:
			L.warning("LDAP server is down.", struct_data={"provider_id": self.ProviderID, "uri": self.LdapUri})
			return False
		except ldap.INVALID_CREDENTIALS:
			L.error("Invalid LDAP credentials.", struct_data={"provider_id": self.ProviderID, "uri": self.LdapUri})
			return False


	async def get_login_descriptors(self, credentials_id: str) -> typing.List[typing.Dict]:
		# Only login with password is supported
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
		ldap_client = _LDAPObject(self.LdapUri)
		ldap_client.protocol_version = ldap.VERSION3
		ldap_client.set_option(ldap.OPT_REFERRALS, 0)

		network_timeout = self.Config.getint("network_timeout")
		ldap_client.set_option(ldap.OPT_NETWORK_TIMEOUT, network_timeout)

		if self.LdapUri.startswith("ldaps"):
			_enable_tls(ldap_client, self.Config)

		ldap_client.simple_bind_s(self.Config["username"], self.Config["password"])
		try:
			yield ldap_client
		finally:
			ldap_client.unbind_s()


	def _get_worker(self, cn: str) -> typing.Optional[typing.Dict]:
		with self._ldap_client() as ldap_client:
			try:
				results = ldap_client.search_s(
					cn,
					ldap.SCOPE_BASE,
					filterstr=self.Filter,
					attrlist=self.AttrList,
				)
			except ldap.NO_SUCH_OBJECT as e:
				raise KeyError("CN matched no LDAP objects.") from e

		if len(results) > 1:
			L.error("CN matched multiple LDAP objects.", struct_data={"CN": cn})
			raise KeyError("CN matched multiple LDAP objects.")

		dn, entry = results[0]
		return self._normalize_credentials(dn, entry)


	def _search_worker(self, filterstr: str) -> typing.List[typing.Dict]:
		# TODO: Implement sorting (Note that not all LDAP servers support server-side sorting)
		results = []
		with self._ldap_client() as ldap_client:
			msgid = ldap_client.search(
				self.Base,
				ldap.SCOPE_SUBTREE,
				filterstr=filterstr,
				attrlist=self.AttrList,
			)
			result_iter = ldap_client.allresults(msgid)

			for res_type, res_data, res_msgid, res_controls in result_iter:
				for dn, entry in res_data:
					if dn is not None:
						results.append(self._normalize_credentials(dn, entry))

		return results


	def _count_worker(self, filterstr: str) -> int:
		count = 0
		with self._ldap_client() as ldap_client:
			msgid = ldap_client.search(
				self.Base,
				ldap.SCOPE_SUBTREE,
				filterstr=filterstr,
				attrsonly=1,  # If attrsonly is non-zero
				attrlist=["cn", "mail", "mobile"],  # For counting, we need only absolutely minimum set of attributes
			)
			result_iter = ldap_client.allresults(msgid)

			for res_type, res_data, res_msgid, res_controls in result_iter:
				for dn, entry in res_data:
					if dn is not None:
						count += 1

		return count


	def _locate_worker(
		self,
		ident: str,
		ident_fields: typing.Optional[typing.Mapping[str, str]] = None
	) -> typing.Optional[str]:
		# TODO: Implement configurable ident_fields support
		with self._ldap_client() as ldap_client:
			msgid = ldap_client.search(
				self.Base,
				ldap.SCOPE_SUBTREE,
				filterstr=ldap.filter.filter_format(
					# Build the filter template
					# Example: (|(cn=%s)(mail=%s)(mobile=%s)(sAMAccountName=%s))
					filter_template="(|{})".format(
						"".join("({}=%s)".format(field) for field in self.IdentFields)),
					assertion_values=tuple(ident for _ in self.IdentFields)
				),
				attrlist=["cn"],
			)
			result_iter = ldap_client.allresults(msgid)
			for res_type, res_data, res_msgid, res_controls in result_iter:
				for dn, entry in res_data:
					if dn is not None:
						return self._format_credentials_id(dn)

		return None


	def _authenticate_worker(self, dn: str, password: str) -> bool:
		ldap_client = _LDAPObject(self.LdapUri)
		ldap_client.protocol_version = ldap.VERSION3
		ldap_client.set_option(ldap.OPT_REFERRALS, 0)

		if self.LdapUri.startswith("ldaps"):
			_enable_tls(ldap_client, self.Config)

		try:
			ldap_client.simple_bind_s(dn, password)
		except ldap.INVALID_CREDENTIALS:
			L.log(asab.LOG_NOTICE, "Authentication failed: Invalid LDAP credentials.", struct_data={"dn": dn})
			return False

		ldap_client.unbind_s()

		return True


	def _normalize_credentials(self, dn: str, search_record: typing.Mapping) -> typing.Dict:
		ret = {
			"_id": self._format_credentials_id(dn),
			"_type": self.Type,
			"_provider_id": self.ProviderID,
		}

		decoded_record = {"dn": dn}
		for k, v in search_record.items():
			if k == "userPassword":
				continue
			if isinstance(v, list):
				if len(v) == 0:
					continue
				elif len(v) == 1:
					decoded_record[k] = v[0].decode("utf-8")
				else:
					decoded_record[k] = [i.decode("utf-8") for i in v]

		v = decoded_record.pop(self.Config["attrusername"], None)
		if v is not None:
			ret["username"] = v
		else:
			# This is fallback, since we need a username on various places
			ret["username"] = dn

		v = decoded_record.pop("cn", None)
		if v is not None:
			ret["full_name"] = v

		v = decoded_record.pop("mail", None)
		if v is not None:
			ret["email"] = v

		v = decoded_record.pop("mobile", None)
		if v is not None:
			ret["phone"] = v

		v = decoded_record.pop("userAccountControl", None)
		if v is not None:
			# userAccountControl is an array of binary flags returned as a decimal integer
			# byte #1 is ACCOUNTDISABLE which corresponds to "suspended" status
			# https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
			try:
				ret["suspended"] = int(v) & 2 == 2
			except ValueError:
				pass

		v = decoded_record.pop("createTimestamp", None)
		if v is not None:
			ret["_c"] = _parse_timestamp(v)
		else:
			v = decoded_record.pop("createTimeStamp", None)
			if v is not None:
				ret["_c"] = _parse_timestamp(v)

		v = decoded_record.pop("modifyTimestamp", None)
		if v is not None:
			ret["_m"] = _parse_timestamp(v)
		else:
			v = decoded_record.pop("modifyTimeStamp", None)
			if v is not None:
				ret["_m"] = _parse_timestamp(v)

		if len(decoded_record) > 0:
			ret["data"] = {k: v for k, v in decoded_record.items() if k in self.AttrList}

		return ret


	def _format_credentials_id(self, obj_id: str) -> str:
		"""
		Encode CN and add provider prefix.
		"""
		return "{}{}".format(
			self.Prefix,
			base64.urlsafe_b64encode(obj_id.encode("utf-8")).decode("ascii")
		)


	def _format_object_id(self, credentials_id: str) -> str:
		"""
		Remove provider prefix and decode CN.
		"""
		if not credentials_id.startswith(self.Prefix):
			raise ValueError("Credentials ID does not start with {!r} prefix.".format(self.Prefix))

		encoded = credentials_id[len(self.Prefix):]
		try:
			cn = base64.urlsafe_b64decode(encoded).decode("utf-8")
		except (binascii.Error, UnicodeDecodeError):
			raise ValueError("Credentials ID is corrupt.")

		return cn


	def _build_search_filter(self, filtr: typing.Optional[str] = None) -> str:
		if not filtr:
			filterstr = self.Filter
		else:
			# The query filter is the intersection of the filter from config
			# and the filter defined by the search request
			# The username must START WITH the given filter string
			filter_template = "(&{}({}=%s*))".format(self.Filter, self.Config["attrusername"])
			assertion_values = ["{}".format(filtr.lower())]
			filterstr = ldap.filter.filter_format(
				filter_template=filter_template,
				assertion_values=assertion_values
			)
		return filterstr


class _LDAPObject(ldap.ldapobject.LDAPObject, ldap.resiter.ResultProcessor):
	pass


def _parse_timestamp(ts: str) -> datetime.datetime:
	try:
		return datetime.datetime.strptime(ts, r"%Y%m%d%H%M%SZ")
	except ValueError:
		pass

	return datetime.datetime.strptime(ts, r"%Y%m%d%H%M%S.%fZ")


def _prepare_attributes(config: typing.Mapping) -> list:
	attr = set(config["attributes"].split(" "))
	attr.add("createTimestamp")
	attr.add("modifyTimestamp")
	attr.add("cn")
	attr.add(config["attrusername"])
	return list(attr)


def _enable_tls(ldap_client, config: typing.Mapping):
	tls_cafile = config["tls_cafile"]

	# Add server certificate authority
	if len(tls_cafile) > 0:
		ldap_client.set_option(ldap.OPT_X_TLS_CACERTFILE, tls_cafile)

	# Set server certificate policy
	if config["tls_require_cert"] == "never":
		ldap_client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
	elif config["tls_require_cert"] == "demand":
		ldap_client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
	elif config["tls_require_cert"] == "allow":
		ldap_client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
	elif config["tls_require_cert"] == "hard":
		ldap_client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_HARD)
	else:
		L.error("Invalid 'tls_require_cert' value: {!r}. Defaulting to 'demand'.".format(
			config["tls_require_cert"]
		))
		ldap_client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)

	# Add client certificate and key
	tls_keyfile = config["tls_keyfile"]
	if tls_keyfile != "":
		ldap_client.set_option(ldap.OPT_X_TLS_KEYFILE, tls_keyfile)

	tls_certfile = config["tls_certfile"]
	if tls_certfile != "":		
		ldap_client.set_option(ldap.OPT_X_TLS_CERTFILE, tls_certfile)

	# Misc TLS options
	tls_protocol_min = config["tls_protocol_min"]
	if tls_protocol_min != "":
		if tls_protocol_min not in _TLS_VERSION:
			raise ValueError("'tls_protocol_min' must be one of {} or empty.".format(list(_TLS_VERSION)))
		ldap_client.set_option(ldap.OPT_X_TLS_PROTOCOL_MIN, _TLS_VERSION[tls_protocol_min])

	tls_protocol_max = config["tls_protocol_max"]
	if tls_protocol_max != "":
		if tls_protocol_max not in _TLS_VERSION:
			raise ValueError("'tls_protocol_max' must be one of {} or empty.".format(list(_TLS_VERSION)))
		ldap_client.set_option(ldap.OPT_X_TLS_PROTOCOL_MAX, _TLS_VERSION[tls_protocol_max])

	if config["tls_cipher_suite"] != "":
		ldap_client.set_option(ldap.OPT_X_TLS_CIPHER_SUITE, config["tls_cipher_suite"])

	# NEWCTX needs to be the last option, because it applies all the prepared options to the new context
	ldap_client.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
