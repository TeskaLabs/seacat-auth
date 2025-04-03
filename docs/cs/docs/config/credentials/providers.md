---
title: Poskytovatelé přihlašovacích údajů
---

# Poskytovatelé přihlašovacích údajů

## MongoDB

- MongoDB je výchozí úložiště pro SeaCat Auth.
- Přihlašovací údaje následují předem definovanou schéma:

```yaml
credential:
    _id: unikátní ID (bson.ObjectId),
    _c: čas vytvoření (UTC timestamp),
    _m: čas poslední úpravy (UTC timestamp),
    _v: verze (int),
    username: (str),
    email: (str),
    phone: (str),
    __password: hash hesla (str),
    suspended: (bool),
    data: další vlastní data (objekt),
```

- Chcete-li přidat poskytovatele MongoDB, přidejte sekci `[seacatauth:credentials:mongodb:<provider_name>]` do konfigurace.


### Příklad konfigurace

```ini
[seacatauth:credentials:mongodb:default]
mongodb_uri=mongodb://mongo:27017
mongodb_database=auth
tenants=yes
register=no
```

---

## Externí MongoDB (`xmongodb`)

- Vhodné pro externí Mongo databáze s přihlašovacími údaji, které neodpovídají schématu očekávanému výchozím poskytovatelem MongoDB.
- *Pouze pro čtení*.
- Chcete-li přidat poskytovatele XMongoDB, přidejte sekci `[seacatauth:credentials:xmongodb:<provider_name>]` do konfigurace.
- Musíte specifikovat agregační pipeline dotazy `list`, `get` a `locate`.
- Výstup agregačního dotazu by měl odpovídat schématu přihlašovacích údajů výchozího poskytovatele MongoDB, tj. objekt přihlašovacích údajů by měl obsahovat unikátní `_id`, `email`, `__password` a volitelně `username` a další pole. Použijte operaci `$project` k mapování vašich databázových polí na tyto aliasy. Další pole ve výstupu jsou považována za součást `custom_data`.

**`POZNÁMKA:`** Znak `$` v dotazech musí být zdvojen jako `$$` (únik je nutný ve formátu configparser).


**Dotaz pro seznam**

- Používá se pro iteraci přes přihlašovací údaje, například v API pro seznam přihlašovacích údajů (`GET /credentials`).
- Očekává se, že výsledek dotazu bude obsahovat `_id`, `username`, `email`, volitelně `phone` a `suspended`. 

**Dotaz pro získání**

- Používá se pro přístup k konkrétním přihlašovacím údajům, například v API pro detail přihlašovacích údajů (`GET /credentials/<credentials_id>`).
- Očekává se, že výsledek dotazu bude obsahovat `_id`, `username`, `email`, `__password`, volitelně `phone` a `suspended`. 
- Použijte operaci `$match` s parametrem `%(_id)s` na místo ID přihlašovacích údajů.

**`POZNÁMKA:`** Použijte `{"$$oid": %(_id)s}` místo `ObjectId(%(_id)s)`.

**Dotaz pro lokalizaci**

- Používá se pro lokalizaci přihlašovacích kandidátů podle `username`, `email`, `phone` nebo jiných polí.
- Očekává se, že výsledek dotazu bude obsahovat `_id`, volitelně `username` a `email`.
- Použijte operaci `$match` s parametrem `%(ident)s` pro shodu přihlašovacích údajů podle identifikátoru (řetězec, který uživatel zadal do přihlašovacího formuláře).

### Příklad konfigurace

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

## LDAP / ActiveDirectory

- Pouze pro čtení
- Deklarováno sekcí `[seacatauth:credentials:ldap:<provider_name>]` v konfiguraci


### Příklad konfigurace

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

## MySQL

- Chcete-li přidat poskytovatele MySQL, přidejte sekci `[seacatauth:credentials:mysql:<provider_id>]` do konfigurace.
- Může být nakonfigurován jako *editovatelný* nebo *pouze pro čtení*.


### Poskytovatel pouze pro čtení

- Poskytovatel MySQL je ve výchozím nastavení pouze pro čtení.
- Dotazy `list`, `get` a `locate` musí být specifikovány.
- Použijte klauzule `AS` k mapování výsledkových polí na očekávaná pole SeaCat Auth `_id`, `username`, `email`, `phone`, `suspended` a `__password`.
- Kde je to nutné, použijte [pojmenované bind proměnné ve stylu `pyformat`](https://legacy.python.org/dev/peps/pep-0249/#paramstyle). 

**Dotaz pro seznam**

- Používá se pro iteraci přes přihlašovací údaje, například v API pro seznam přihlašovacích údajů (`GET /credentials`).
- Očekává se, že výsledek dotazu bude obsahovat `_id`, `username`, `email`, volitelně `phone` a `suspended`. 
Použijte klauzule `AS` k přidání těchto aliasů k databázovým polím.
- Použijte klauzuli `ORDER BY` pro zajištění konstantního pořadí.

**Dotaz pro získání**

- Používá se pro přístup k konkrétním přihlašovacím údajům, například v API pro detail přihlašovacích údajů (`GET /credentials/<credentials_id>`).
- Očekává se, že výsledek dotazu bude obsahovat `_id`, `username`, `email`, `__password`, volitelně `phone` a `suspended`. 
Použijte klauzule `AS` k přidání těchto aliasů k databázovým polím.
- Použijte klauzuli `WHERE` s bind parametrem `%(_id)s` pro shodu databázového objektu podle jeho ID.
- Další datová pole, která by měla být zahrnuta v objektu přihlašovacích údajů, musí být také uvedena v konfiguraci jako `data_fields`.

**Dotaz pro lokalizaci**

- Používá se pro lokalizaci přihlašovacích kandidátů podle `username`, `email`, `phone` nebo jiných polí.
- Očekává se, že výsledek dotazu bude obsahovat `_id`, volitelně `username` a `email`.
- Použijte klauzuli `WHERE` s bind parametrem `%(ident)s` pro shodu přihlašovacích údajů podle identifikátoru (řetězec, který uživatel zadal do přihlašovacího formuláře).


#### Příklad konfigurace

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


### Editovatelný poskytovatel

- Chcete-li povolit vytváření, aktualizaci a mazání uživatelů, specifikujte `editable=yes` v konfiguraci.
- To vyžaduje specifikaci dotazů `create`, `update` a `delete`.

#### Příklad konfigurace

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


## Htpasswd

- Pouze pro čtení
- Chcete-li vytvořit poskytovatele htpasswd, přidejte sekci `[seacatauth:credentials:htpasswd:<provider_name>]` do konfigurace 
  a specifikujte cestu k vašemu htpasswd souboru.
- Nový htpasswd soubor můžete vytvořit pomocí příkazu `htpasswd`, například
```bash
htpasswd /opt/site/seacatauth-conf/htpasswd john-smith
```

### Příklad konfigurace

```ini
[seacatauth:credentials:htpasswd:local]
path=/conf/htpasswd
```

---


## V paměti (Slovník)

- Neperzistentní editovatelný poskytovatel
- Deklarováno sekcí `[seacatauth:credentials:dict:<provider_name>]` v konfiguraci


### Příklad konfigurace

```ini
[seacatauth:credentials:dict:inmemory]

```