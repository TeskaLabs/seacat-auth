"""Synchronize LDAP group membership to SeaCat Auth roles and tenants in MongoDB.

Run from the repository root (or pass absolute paths)::

    python scripts/ldap-access-sync.py -c /path/to/seacatauth.conf -m /path/to/group-map.yaml

"""

import ldap
import ldap.resiter
import ldap.filter
import json
import logging
import base64
import contextlib
import pymongo
import configparser
import argparse
import os
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

try:
    import yaml
except ImportError:
    yaml = None

L = logging.getLogger(__name__)
MANAGED_BY = "lmio-access-sync"


@dataclass
class Config:
    ldap_username: Optional[str] = None
    ldap_password: Optional[str] = None
    ldap_uri: Optional[str] = None
    ldap_base_dn: Optional[str] = None
    ldap_filter: Optional[str] = None
    ldap_attributes: List[str] = field(default_factory=list)
    ldap_network_timeout: int = 5
    # TLS/SSL options for LDAPS
    ldap_tls_cafile: Optional[str] = None
    ldap_tls_require_cert: Optional[str] = None
    ldap_tls_keyfile: Optional[str] = None
    ldap_tls_certfile: Optional[str] = None
    ldap_tls_protocol_min: Optional[str] = None
    ldap_tls_protocol_max: Optional[str] = None
    ldap_tls_cipher_suite: Optional[str] = None
    cred_id_prefix: Optional[str] = None
    mongodb_uri: Optional[str] = None
    mongodb_db: Optional[str] = None
    group_map: Optional[Dict[str, Any]] = None


class _LDAPObject(ldap.ldapobject.LDAPObject, ldap.resiter.ResultProcessor):
    pass


@contextlib.contextmanager
def ldap_client(cfg):
    """Context manager for LDAP client connection.

    Args:
        cfg (Config): The configuration object containing LDAP connection parameters.

    Yields:
        _LDAPObject: An LDAP client object, already bound.

    Raises:
        NotImplementedError: If LDAPS is requested (not supported).
    """
    client = _LDAPObject(cfg.ldap_uri)
    client.protocol_version = ldap.VERSION3
    client.set_option(ldap.OPT_REFERRALS, 0)
    client.set_option(ldap.OPT_NETWORK_TIMEOUT, cfg.ldap_network_timeout)
    if cfg.ldap_uri is not None and isinstance(cfg.ldap_uri, str) and cfg.ldap_uri.startswith("ldaps"):
        _enable_tls(client, cfg)
    client.simple_bind_s(cfg.ldap_username, cfg.ldap_password)
    try:
        yield client
    finally:
        client.unbind_s()


def iter_ldap_search_paged(
    client,
    base_dn: str,
    scope: int,
    filterstr: str,
    attrlist: List[str],
    page_size: int = 500,
):
    """Iterate LDAP search results using RFC 2696 paged results.

    This avoids server-side sizeLimit issues when a subtree is large.
    """
    paged = ldap.controls.SimplePagedResultsControl(True, size=page_size, cookie=b"")
    msgid = client.search_ext(base_dn, scope, filterstr, attrlist=attrlist, serverctrls=[paged])

    while True:
        rtype, rdata, rmsgid, serverctrls = client.result3(msgid)
        for dn, entry in rdata:
            if dn:
                yield dn, entry

        cookie = None
        for ctrl in serverctrls or []:
            if ctrl.controlType == ldap.controls.SimplePagedResultsControl.controlType:
                cookie = ctrl.cookie
                break

        if not cookie:
            break

        paged.cookie = cookie
        msgid = client.search_ext(base_dn, scope, filterstr, attrlist=attrlist, serverctrls=[paged])


def _enable_tls(client, cfg):
    """Enable TLS/SSL for an LDAP client using config options.

    Args:
        client (_LDAPObject): The LDAP client object.
        cfg (Config): The configuration object with TLS options.
    """
    # CA file
    tls_cafile = getattr(cfg, 'ldap_tls_cafile', None) or ''
    if tls_cafile:
        client.set_option(ldap.OPT_X_TLS_CACERTFILE, tls_cafile)
    # Certificate policy
    tls_require_cert = getattr(cfg, 'ldap_tls_require_cert', 'never')
    if tls_require_cert == 'never':
        client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    elif tls_require_cert == 'demand':
        client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
    elif tls_require_cert == 'allow':
        client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
    elif tls_require_cert == 'hard':
        client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_HARD)
    else:
        L.error(f"Invalid 'ldap_tls_require_cert' value: {tls_require_cert!r}. Defaulting to 'demand'.")
        client.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
    # Client cert/key
    tls_keyfile = getattr(cfg, 'ldap_tls_keyfile', None) or ''
    if tls_keyfile:
        client.set_option(ldap.OPT_X_TLS_KEYFILE, tls_keyfile)
    tls_certfile = getattr(cfg, 'ldap_tls_certfile', None) or ''
    if tls_certfile:
        client.set_option(ldap.OPT_X_TLS_CERTFILE, tls_certfile)
    # Protocol min/max
    _TLS_VERSION = {
        "1.0": ldap.OPT_X_TLS_PROTOCOL_TLS1_0,
        "1.1": ldap.OPT_X_TLS_PROTOCOL_TLS1_1,
        "1.2": ldap.OPT_X_TLS_PROTOCOL_TLS1_2,
        "1.3": ldap.OPT_X_TLS_PROTOCOL_TLS1_3,
    }
    tls_protocol_min = getattr(cfg, 'ldap_tls_protocol_min', '')
    if tls_protocol_min:
        if tls_protocol_min not in _TLS_VERSION:
            raise ValueError(f"'ldap_tls_protocol_min' must be one of {_TLS_VERSION.keys()} or empty.")
        client.set_option(ldap.OPT_X_TLS_PROTOCOL_MIN, _TLS_VERSION[tls_protocol_min])
    tls_protocol_max = getattr(cfg, 'ldap_tls_protocol_max', '')
    if tls_protocol_max:
        if tls_protocol_max not in _TLS_VERSION:
            raise ValueError(f"'ldap_tls_protocol_max' must be one of {_TLS_VERSION.keys()} or empty.")
        client.set_option(ldap.OPT_X_TLS_PROTOCOL_MAX, _TLS_VERSION[tls_protocol_max])
    # Cipher suite
    tls_cipher_suite = getattr(cfg, 'ldap_tls_cipher_suite', '')
    if tls_cipher_suite:
        client.set_option(ldap.OPT_X_TLS_CIPHER_SUITE, tls_cipher_suite)
    # Apply all options
    client.set_option(ldap.OPT_X_TLS_NEWCTX, 0)


def credentials_id_from_dn(cfg, dn: str) -> str:
    """Generate a credentials ID from a DN using the configured prefix and base64 encoding.

    Args:
        cfg (Config): The configuration object containing the credential ID prefix.
        dn (str): The LDAP distinguished name.

    Returns:
        str: The generated credentials ID.
    """
    return "{}{}".format(
        cfg.cred_id_prefix,
        base64.urlsafe_b64encode(dn.encode("utf-8")).decode("ascii")
    )


@contextlib.contextmanager
def mongodb_database(cfg):
    """Open one MongoDB client for the lifetime of the context.

    Args:
        cfg (Config): The configuration object with MongoDB URI and database name.

    Yields:
        pymongo.database.Database: The configured database.

    Raises:
        RuntimeError: If MongoDB URI or DB is not set in the config.
    """
    if not cfg.mongodb_uri or not cfg.mongodb_db:
        raise RuntimeError("MongoDB URI or DB not set. Did you call load_mongodb_config()?")
    client = pymongo.MongoClient(cfg.mongodb_uri)
    try:
        yield client[cfg.mongodb_db]
    finally:
        client.close()


def list_tenants(db, cred_id: str):
    """List all tenants assigned to a given credentials ID.

    Args:
        db (pymongo.database.Database): MongoDB database handle.
        cred_id (str): The credentials ID.

    Returns:
        list[str]: List of tenant IDs.
    """
    collection = db["ct"]
    return [obj["t"] for obj in collection.find({"c": cred_id, "managed_by": MANAGED_BY})]


def assign_tenant(db, cred_id: str, tenant: str):
    """Assign a tenant to a credentials ID in MongoDB.

    Args:
        db (pymongo.database.Database): MongoDB database handle.
        cred_id (str): The credentials ID.
        tenant (str): The tenant ID to assign.
    """
    collection = db["ct"]
    obj_id = "{} {}".format(cred_id, tenant)
    result = collection.update_one(
        {"_id": obj_id},
        {"$set": {"c": cred_id, "t": tenant, "managed_by": MANAGED_BY}},
        upsert=True
    )
    if result and result.did_upsert:
        print("Assigned tenant {!r} to credentials {!r}".format(tenant, cred_id))


def unassign_tenant(db, cred_id: str, tenant: str):
    """Unassign a tenant from a credentials ID in MongoDB.

    Args:
        db (pymongo.database.Database): MongoDB database handle.
        cred_id (str): The credentials ID.
        tenant (str): The tenant ID to unassign.
    """
    collection = db["ct"]
    obj_id = "{} {}".format(cred_id, tenant)
    obj = collection.find_one_and_delete({"_id": obj_id, "managed_by": MANAGED_BY})
    if obj:
        print("Unassigned tenant {!r} from credentials {!r}".format(tenant, cred_id))


def list_roles(db, cred_id: str):
    """List all roles assigned to a given credentials ID.

    Args:
        db (pymongo.database.Database): MongoDB database handle.
        cred_id (str): The credentials ID.

    Returns:
        list[str]: List of role IDs.
    """
    collection = db["cr"]
    return [obj["r"] for obj in collection.find({"c": cred_id, "managed_by": MANAGED_BY})]


def assign_role(db, cred_id: str, role: str):
    """Assign a role to a credentials ID in MongoDB.

    Args:
        db (pymongo.database.Database): MongoDB database handle.
        cred_id (str): The credentials ID.
        role (str): The role ID to assign.
    """
    collection = db["cr"]
    obj_id = "{} {}".format(cred_id, role)
    obj = {"c": cred_id, "r": role, "managed_by": MANAGED_BY}
    if (tenant := role.split("/")[0]) != "*":
        obj["t"] = tenant.lstrip("~")
    result = collection.update_one(
        {"_id": obj_id},
        {"$set": obj},
        upsert=True
    )
    if result and result.did_upsert:
        print("Assigned role {!r} to credentials {!r}".format(role, cred_id))


def unassign_role(db, cred_id: str, role: str):
    """Unassign a role from a credentials ID in MongoDB.

    Args:
        db (pymongo.database.Database): MongoDB database handle.
        cred_id (str): The credentials ID.
        role (str): The role ID to unassign.
    """
    collection = db["cr"]
    obj_id = "{} {}".format(cred_id, role)
    obj = collection.find_one_and_delete({"_id": obj_id, "managed_by": MANAGED_BY})
    if obj:
        print("Unassigned role {!r} from credentials {!r}".format(role, cred_id))


def load_ldap_config(config_path):
    """Load LDAP configuration from a config file.

    Args:
        config_path (str): Path to the config file.

    Returns:
        Config: The configuration object populated with LDAP settings.

    Raises:
        FileNotFoundError: If ``config_path`` is not a regular file.
        RuntimeError: If no or multiple LDAP provider sections are found.
    """
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    parser = configparser.ConfigParser()
    parser.read(config_path)
    ldap_sections = [s for s in parser.sections() if s.startswith('seacatauth:credentials:ldap:')]
    if len(ldap_sections) == 0:
        raise RuntimeError(f"No [seacatauth:credentials:ldap:*] section found in config {config_path}")
    if len(ldap_sections) > 1:
        raise RuntimeError(f"Multiple LDAP provider sections found: {ldap_sections}. Please keep only one.")
    section = ldap_sections[0]
    cfg = Config()
    cfg.ldap_username = parser[section].get('username')
    cfg.ldap_password = parser[section].get('password')
    cfg.ldap_uri = parser[section].get('uri')
    cfg.ldap_base_dn = parser[section].get('base')
    cfg.ldap_filter = parser[section].get('filter')
    cfg.ldap_attributes = parser[section].get('attributes', 'mail mobile userAccountControl displayName memberOf sAMAccountName').split()
    cfg.ldap_network_timeout = int(parser[section].get('network_timeout', '5'))
    cfg.cred_id_prefix = section.replace('seacatauth:credentials:', '') + ':'
    # Load TLS/SSL options
    cfg.ldap_tls_cafile = parser[section].get('tls_cafile')
    cfg.ldap_tls_require_cert = parser[section].get('tls_require_cert')
    cfg.ldap_tls_keyfile = parser[section].get('tls_keyfile')
    cfg.ldap_tls_certfile = parser[section].get('tls_certfile')
    cfg.ldap_tls_protocol_min = parser[section].get('tls_protocol_min')
    cfg.ldap_tls_protocol_max = parser[section].get('tls_protocol_max')
    cfg.ldap_tls_cipher_suite = parser[section].get('tls_cipher_suite')
    return cfg


def load_group_map(path):
    """Load the group map from a YAML or JSON file.

    Args:
        path (str): Path to the group map file (YAML or JSON).

    Returns:
        dict: The group map as a dictionary.

    Raises:
        FileNotFoundError: If ``path`` is not a regular file.
        RuntimeError: If the file has an unsupported extension or PyYAML is not installed for YAML files.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Group map file not found: {path}")
    with open(path, 'r', encoding='utf-8') as f:
        if path.endswith('.yaml') or path.endswith('.yml'):
            if yaml is None:
                raise RuntimeError("PyYAML is required for YAML group map files. Install with 'pip install pyyaml'.")
            return yaml.safe_load(f)
        elif path.endswith('.json'):
            return json.load(f)
        else:
            raise RuntimeError("Group map file must be .yaml, .yml, or .json")


def load_mongodb_config(config_path, cfg):
    """Load MongoDB configuration from a config file and update the config object.

    Args:
        config_path (str): Path to the config file.
        cfg (Config): The configuration object to update.

    Returns:
        Config: The updated configuration object.

    Raises:
        RuntimeError: If the [mongo] section or required keys are missing.
    """
    parser = configparser.ConfigParser()
    parser.read(config_path)
    if 'mongo' not in parser:
        raise RuntimeError(f"Missing [mongo] section in config {config_path}")
    cfg.mongodb_uri = parser['mongo'].get('uri')
    cfg.mongodb_db = parser['mongo'].get('database')
    if not cfg.mongodb_uri or not cfg.mongodb_db:
        raise RuntimeError(f"Missing 'uri' or 'database' in [mongo] section of {config_path}")
    return cfg


def main():
    """Main entry point for the LDAP-to-MongoDB sync script.

    Parses command-line arguments, loads configuration, and synchronizes LDAP users to MongoDB roles and tenants.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='Path to config file', default='/conf/seacatauth.conf')
    parser.add_argument('-m', '--group-map', help='Path to group map YAML or JSON file', default='/conf/ldap-group-map.yaml')
    args = parser.parse_args()

    cfg = load_ldap_config(args.config)
    cfg = load_mongodb_config(args.config, cfg)
    cfg.group_map = load_group_map(args.group_map)

    with mongodb_database(cfg) as db, ldap_client(cfg) as client:
        for dn, entry in iter_ldap_search_paged(
            client,
            cfg.ldap_base_dn,
            ldap.SCOPE_SUBTREE,
            cfg.ldap_filter,
            cfg.ldap_attributes,
        ):

            cid = credentials_id_from_dn(cfg, dn)
            member_of = [s.decode() for s in entry.get("memberOf", [])]
            desired_roles = set()
            desired_tenants = set()
            for group_dn, mapping in cfg.group_map.items():
                if not mapping:
                    continue
                if group_dn in member_of:
                    desired_tenants.update(mapping.get("tenants", []))
                    desired_roles.update(mapping.get("roles", []))

            current_roles = set(list_roles(db, cid))
            current_tenants = set(list_tenants(db, cid))

            for tenant in sorted(desired_tenants - current_tenants):
                assign_tenant(db, cid, tenant)
            for role in sorted(desired_roles - current_roles):
                assign_role(db, cid, role)

            for tenant in sorted(current_tenants - desired_tenants):
                unassign_tenant(db, cid, tenant)
            for role in sorted(current_roles - desired_roles):
                unassign_role(db, cid, role)


if __name__ == "__main__":
    main()
