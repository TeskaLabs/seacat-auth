---
title: SeaCat Auth a LDAP nebo Active Directory
---

# SeaCat Auth a LDAP nebo Active Directory

## Spuštění LDAP serveru v docker kontejneru

```bash
docker run -p 389:389 -p 636:636 --rm --name open-ldap osixia/openldap:1.3.0
```

## Vyhledávání uživatelů v LDAP kontejneru

```bash
# (-x) Jednoduchá autentizace, (-H)ost, -(b)ázové dn pro vyhledávání, (-D) bind DN, (-w) heslo
docker exec open-ldap ldapsearch -x -H ldap://localhost -b dc=example,dc=org -D "cn=admin,dc=example,dc=org" -w admin
```

## Nastavení konfiguračního souboru

```ini
[general]
identity_provider_url=ldap://localhost
```