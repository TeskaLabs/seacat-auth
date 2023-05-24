---
title: SeaCat Auth configuration
---

# SeaCat Auth configuration

SeaCat Auth is primarily configured via a `.conf` file.
For general info about configuration (syntax etc.), refer to the respective 
page in [ASAB docs](https://asab.readthedocs.io/en/latest/asab/config.html).

## Config file example

This is how a SeaCat Auth config file can look like:

```ini
[general]
public_api_base_url=http://localhost/seacat_auth/api
auth_webui_base_url=http://localhost/auth
include=/conf/secret.conf

[logging:file]
path=/log/seacat-auth.log

[web]
listen=0.0.0.0 8082

[web:public]
listen=0.0.0.0 8081

[asab:storage]
type=mongodb
mongodb_uri=mongodb://mongo:27017/
mongodb_database=auth

[seacatauth:credentials]
policy_file=/conf/credentials-policy.json
ident_fields=username:ignorecase email:ignorecase

[seacatauth:credentials:mongodb:default]
mongodb_uri=mongodb://mongo:27017
mongodb_database=auth
tenants=yes
register=no

[seacatauth:credentials:htpasswd:file]
path=/conf/htpasswd

[seacatauth:google]
; client_id in secret.conf
; client_secret in secret.conf

[seacatauth:cookie]
name=SeaCatSCI
domain=localhost

[seacatauth:session]
expiration=1h
touch_extension=0.5
maximum_age=30d
; aes_key in secret.conf

[seacatauth:communication:email:smtp]
sender_email_address=info@teskalabs.com
host=smtp.sendgrid.net
ssl=no
starttls=yes
; user in secret.conf
; password in secret.conf
```
