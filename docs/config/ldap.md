---
title: SeaCat Auth and LDAP or Active directory
---

# SeaCat Auth and LDAP or Active directory

## Starting LDAP server in a docker container

```bash
docker run -p 389:389 -p 636:636 --rm --name open-ldap osixia/openldap:1.3.0
```

## Search users in LDAP container

```bash
# (-x) Simple auth, (-H)ost, -(b)ase dn for search, (-D) bind DN, (-w) password
docker exec open-ldap ldapsearch -x -H ldap://localhost -b dc=example,dc=org -D "cn=admin,dc=example,dc=org" -w admin
```

## Setup configuration file

```ini
[general]
identity_provider_url=ldap://localhost
```
