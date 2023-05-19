---
layout: default
title: TeskaLabs SeaCat Auth Documentation
---

# Credentials providers

* This will become a table of contents (this text will be scrapped).
{:toc}

---

# MongoDB

- MongoDB is the default storage backend for SeaCat Auth.
- Credentials follow a predefined schema:

```yaml
credential:
    _id: unique ID (bson.ObjectId),
    _c: creation time (UTC timestamp),
    _m: last modification time (UTC timestamp),
    _v: version (int),
    username: (str),
    email: (str),
    phone: (str),
    __password: password hash (str),
    suspended: (bool),
    data: additional custom data (object),
```

- To add a MongoDB provider, add a `[seacatauth:credentials:mongodb:<provider_name>]` section in the config.


## Example config

```ini
[seacatauth:credentials:mongodb:default]
mongodb_uri=mongodb://mongo:27017
mongodb_database=auth
tenants=yes
register=no
```

---

# External MongoDB (`xmongodb`)

- Suitable for external Mongo databases with credentials that do not follow the schema expected by the default MongoDB provider.
- *Read-only*.
- To add a XMongoDB provider, add a `[seacatauth:credentials:xmongodb:<provider_name>]` section in the config.
- You must specify the `list`, `get` and `locate` aggregation pipelines/queries.
- The output of the aggregation query should match the credential schema of the default MongoDB provider, i.e. the credentials object should contain a unique `_id`, `email`, `__password` and optionally `username` and the other fields. Use the `$project` operation to map your database fields to these aliases. Additional fields in the output are considered to be part of `custom_data`.

**`NOTE:`** The `$` sign in the queries must be doubled as `$$` (escape necessary in the configparser format).


**List query**

- Used for iterating through credentials, for example in credentials list API (`GET /credentials`).
- Query result is expected to  contain `_id`, `username`, `email`, optionally `phone` and `suspended`. 

**Get query**

- Used for accessing spectific credentials, for example in credentials detail API (`GET /credentials/<credentials_id>`).
- Query result is expected to contain `_id`, `username`, `email`, `__password`, optionally `phone` and `suspended`. 
- Use the `$match` operation with the bind parameter `%(_id)s` in place of the credential ID.

**`NOTE:`** Use `{"$$oid": %(_id)s}` instead of `ObjectId(%(_id)s)`.

**Locate query**

- Used for locating login candidates by `username`, `email`, `phone` or other fields.
- Query result is expected to contain `_id`, optionally `username` and `email`.
- Use the `$match` operation with the bind parameter `%(ident)s` to match credentials by ident (the string that the user entered in the login form).

## Example config

```ini
[seacatauth:credentials:xmongodb:users]
mongodb_uri=mongodb://localhost:27017
database=test
collection=users
list=
    [
        {"$$project": {
            "_id": true,
            "username": true,
            "email": true,
            "phone": true,
            "suspended": true
        }}
    ]
get=
    [
        {"$$match": {
            "_id": {"$$oid": %(_id)s}
        }},
        {"$$project": {
            "_id": true,
            "username": true,
            "email": true,
            "phone": true,
            "suspended": true,
            "likes": true,
            "__password": true
        }}
    ]
locate=
    [
        {"$$match": {
            "$$or": [
                {
                    "username": %(ident)s
                },
                {
                    "email": %(ident)s
                }
            ]
        }},
        {"$$project": {
            "_id": true,
            "username": true,
            "email": true,
            "phone": true,
            "suspended": true
        }}
    ]

```

---

# LDAP / ActiveDirectory

- Read-only
- Declared by `[seacatauth:credentials:ldap:<provider_name>]` config section


## Example config

```ini
[seacatauth:credentials:ldap:external]
uri=ldaps://localhost:636
base=OU=Users,OU=Employees,DC=ThisCompany,DC=local
filter=(cn=*)
attrusername=sAMAccountName
tls_cafile=/conf/secret/local-ldap-cert.pem
tls_require_cert=allow

```


---

# MySQL

- To add a MySQL provider, add a `[seacatauth:credentials:mysql:<provider_id>]` section in the config.
- It can be configured to be either *editable* or *read-only*.


## Read-only provider

- MySQL provider is read-only by default.
- `list`, `get` and `locate` queries must be specified.
- Use `AS` clauses to map the result fields to expected SeaCat Auth fields `_id`, `username`, `email`, `phone`, `suspended` and `__password`.
- Where needed, use [`pyformat`-style named bind variables](https://legacy.python.org/dev/peps/pep-0249/#paramstyle). 

**List query**

- Used for iterating through credentials, for example in credentials list API (`GET /credentials`).
- Query result is expected to contain `_id`, `username`, `email`, optionally `phone` and `suspended`. 
Use `AS` clauses to add these aliases to the database fields.
- Use `ORDER BY` clause to ensure constant ordering.

**Get query**

- Used for accessing spectific credentials, for example in credentials detail API (`GET /credentials/<credentials_id>`).
- Query result is expected to contain `_id`, `username`, `email`, `__password`, optionally `phone` and `suspended`. 
Use `AS` clauses to add these aliases to the database fields.
- Use `WHERE` clause with the bind parameter `%(_id)s` to match the database object by its id.
- Additional data fields which should be included in the credentials object must be also listed in configuration as `data_fields`.

**Locate query**

- Used for locating login candidates by `username`, `email`, `phone` or other fields.
- Query result is expected to contain `_id`, optionally `username` and `email`.
- Use `WHERE` clause with the bind parameter `%(ident)s` to match credentials by ident (the string that the user entered in the login form).


### Example config

```
[seacatauth:credentials:mysql:external]
host=localhost
port=3306
user=root
password=rootpassword
database=auth
data_fields=firstName lastName
list=
    SELECT `id` AS '_id', `userName` AS 'username', `userEmail` AS 'email', `userPhone` AS 'phone'
    FROM `users` 
    ORDER BY `id` ASC;
get=
    SELECT `id` AS '_id', `userName` AS 'username', `userEmail` AS 'email', `userPhone` AS 'phone', `userPwd` AS '__password', `userSuspened` AS 'suspended', firstName, lastName
    FROM `users` 
    WHERE `id` = %(_id)s;
locate=
    SELECT `id` AS '_id', `userName`, `userEmail`
    FROM `users` 
    WHERE (LOWER(`userName`) = %(ident)s) OR (LOWER(`userEmail`) = %(ident)s);
```

---


## Editable provider

- To enable creating, updating and deleting users, specify `editable=yes` in config.
- This requires specifying the `create`, `update` and `delete` queries.

### Example config

```
[seacatauth:credentials:mysql:external]
editable=yes
user=root
password=rootpassword
database=auth
data_fields=firstName lastName
list=
    SELECT `id` AS '_id', `userName` AS 'username', `userEmail` AS 'email', `userPhone` AS 'phone'
    FROM `users` 
    ORDER BY `id` ASC;
get=
    SELECT `id` AS '_id', `userName` AS 'username', `userEmail` AS 'email', `userPhone` AS 'phone', `userPwd` AS '__password',  `userSuspened` AS 'suspended', firstName, lastName
    FROM `users` 
    WHERE `id` = %(_id)s;
locate=
    SELECT `id` AS '_id', `userName`, `userEmail`
    FROM `users` 
    WHERE (LOWER(`userName`) = %(ident)s) OR (LOWER(`userEmail`) = %(ident)s);
create=
    INSERT INTO `users` 
    (`userName`, `userEmail`, `userPhone`) 
    VALUES (%(username)s, %(email)s, %(phone)s);
update=
    UPDATE `users` 
    SET `userEmail` = %(email)s, `userPhone` = %(phone)s, `userSuspened` = %(suspended)s, `userPwd` = %(__password)s
    WHERE `id` = %(_id)s;
delete=
    DELETE FROM `users` 
    WHERE `id` = %(_id)s;
```

---


# Htpasswd

- Read-only
- To create a htpasswd provider, add a `[seacatauth:credentials:htpasswd:<provider_name>]` section in the config 
  and specify a path to your htpasswd file.
- You can create a new htpasswd file using the `htpasswd` command, for example
```bash
htpasswd /opt/site/seacatauth-conf/htpasswd john-smith
```

## Example config

```ini
[seacatauth:credentials:htpasswd:local]
path=/conf/htpasswd
```

---


# In-memory (Dictionary)

- Non-persistent editable provider
- Declared by `[seacatauth:credentials:dict:<provider_name>]` config section


## Example config

```ini
[seacatauth:credentials:dict:inmemory]

```
