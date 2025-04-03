---
title: HTTP Cookies
---

# HTTP Cookies 🍪

SeaCat Auth poskytuje autentizaci založenou na cookies pro aplikace, které neimplementují OAuth2. 
Pro [jednodoménové](#single-domain-setting) a [vícedoménové](#multi-domain-setting) nastavení je potřeba odlišná konfigurace.

## <a name="single-domain-setting"></a> Jednodoménové nastavení

Pokud všechny aplikace, které chcete chránit, běží na stejné doméně jako vaše služba SeaCat Auth (nebo její subdomény), 
musíte nakonfigurovat pouze **hlavní cookie**. 
Tato cookie je uživateli automaticky odeslána po úspěšném přihlášení.

### Konfigurace služby

Hlavní cookie je nakonfigurována v sekci `[seacatauth:cookie]`. 
Dostupné možnosti konfigurace jsou:
- `name`: Název cookie, výchozí hodnota je `SeaCatSCI`
- `domain`: Doména cookie. Nemá žádnou výchozí hodnotu a musí být explicitně nakonfigurována.

**`POZNÁMKA:`** Aby cookie fungovala ve všech hlavních prohlížečích, musí doména cookie obsahovat alespoň dvě tečky (požadavek od Firefoxu). 
Například `localhost` nebo `.xyz` nemusí fungovat správně, ale `.app.localhost` nebo `.example.xyz` by měly fungovat bez problémů.

#### Příklad

```ini
[seacatauth:cookie]
domain=.service.xyz
```

*Taková cookie je platná na doméně `service.xyz` a všech jejích subdoménách a subcestách, 
například `auth.service.xyz` nebo `myapp.test.service.xyz/example`.*

### Nastavení introspekce cookie

Introspekce cookie je způsob autentizace a autorizace požadavků na chráněné místo. 
Každý uživatelský požadavek na takové místo je kontrolován, zda má platnou cookie SeaCat Auth v hlavičce. 
Pokud ano, požadavek pokračuje na chráněné místo. 
Pokud nemá platnou cookie, je uživateli odeslána odpověď `HTTP 401 Not Authorized`. 
Nebo může být uživatel přímo přesměrován na koncový bod autorizace.

Koncový bod introspekce cookie se nachází na cestě `/nginx/introspect/cookie` a používá `POST` požadavky. 
Dále má schopnost přidávat určité informace o uživateli do HTTP X-hlavic, 
například uživatelské jméno, role nebo nájemce. 
To se provádí pomocí `add=` dotazových parametrů v introspekčním volání. 
*Podívejte se na kolekci SeaCat Auth Postman pro více informací o tomto koncovém bodu.*

Konfigurace koncového bodu introspekce:

```nginx
location = /_cookie_introspect {
    internal;
    proxy_method          POST;
    proxy_set_body        "$http_authorization";
    proxy_pass            <SEACAT_AUTH_SERVICE_URL>/nginx/introspect/cookie;
    proxy_ignore_headers  Cache-Control Expires Set-Cookie;
}
```

Příklad konfigurace chráněného místa pomocí cookie:

```nginx
location / {
    proxy_pass <PROTECTED_LOCATION_URL>;
    
    auth_request        /_cookie_introspect;
    auth_request_set    $authorization $upstream_http_authorization;
    proxy_set_header    Authorization $authorization;
}
```

## <a name="multi-domain-setting"></a> Vícedoménové nastavení

Pokud některé z vašich aplikací běží na jiných doménách než služba SeaCat Auth, 
musíte nastavit **aplikaci cookie** a **koncový bod pro vstup cookie** pro každou z těchto domén. 
Na rozdíl od *hlavní cookie* nejsou tyto cookies automaticky vydávány po přihlášení. 
Aby je bylo možné získat, je nutné provést volání požadavku na cookie.

### Tok požadavku na cookie

❓ TODO: Tok uživatele bez autentizace ❓

- Uživatel se pokouší přistupovat k chráněnému místu bez požadované aplikace cookie
- Introspekce cookie NGINX selže a uživatel je přesměrován na koncový bod OIDC autorizace
- Koncový bod autorizace přesměrovává uživatele na přihlašovací obrazovku
- Uživatel se přihlásí
- Uživatel je přesměrován na koncový bod žádosti o aplikaci cookie s autentizačním kódem v dotazovacím řetězci
- Koncový bod žádosti o cookie vymění autentizační kód za cookie 
  a přesměruje uživatele na předem nakonfigurovanou URL

### Konfigurace

Každá cookie je nakonfigurována ve své vlastní sekci nazvané `[seacatauth:cookie:<APP_DOMAIN_ID>]`. 
`<DOMAIN_ID>` se používá v URL požadavku na cookie pro odpovídající doménu.

```ini
[seacatauth:cookie]
; Toto je hlavní cookie, je vyžadována jak v jednodoménovém, tak ve vícedoménovém nastavení
domain=auth.service.xyz

[seacatauth:cookie:myservice]
domain=my.service.xyz
redirect_uri=http://my.service.xyz/home

[seacatauth:cookie:anotherservice]
domain=service.elsewhere.xyz
redirect_uri=http://service.elsewhere.xyz/discover
```

`redirect_uri` určuje, kam je uživatel přesměrován po úspěšném požadavku na cookie.

### Koncový bod pro vstup cookie

`GET /cookie/entry/<APP_DOMAIN_ID>`

Vyměňuje autorizační kód za aplikaci cookie. 
Je nutné poskytnout dotazové parametry `grant_type=authorization_code` a `code=......` v požadavku.

Např.:

`GET http://my.service.xyz/auth/cookie/entry/myservice?grant_type=authorization_code&code=4x0fDvBTuSM3dWlp7t2560A4wtCB199dcbLU5pphe8AagCpM`

### Konfigurace NGINX

Každá z nakonfigurovaných domén musí mít proxy na **introspekci cookie** a **požadavek na cookie** koncové body. 
Koncový bod introspekce je nakonfigurován přesně stejně jako v případě jednodoménového nastavení:

```nginx
location = /_cookie_introspect {
    internal;
    proxy_method          POST;
    proxy_set_body        "$http_authorization";
    proxy_pass            <SEACAT_AUTH_PUBLIC_API_INTERNAL_URL>/nginx/introspect/cookie;
    proxy_ignore_headers  Cache-Control Expires Set-Cookie;
}
```

- `<SEACAT_AUTH_PUBLIC_API_INTERNAL_URL>` je interní základní URL vaší veřejné API SeaCat Auth.

Místa, která používají introspekci cookie, by měla nastavit svou chybovou stránku na koncový bod OIDC autorizace 
s `scope=openid&response_type=code` pro automatické vyzvání k přihlášení. 
URL pro přesměrování by měla směřovat na **požadavek na cookie** koncový bod s `grant_type=authorization_code`:

```nginx
server_name <APP_DOMAIN>

...

location /auth/cookie_entry {
	proxy_pass <SEACAT_AUTH_PUBLIC_API_INTERNAL_URL>/cookie/entry/<APP_DOMAIN_ID>;
}
```

- `<APP_DOMAIN>` je vaše aplikační doména, odlišná od domény SeaCat Auth.
- `<APP_DOMAIN_ID>` je ID vaší aplikační domény, jak jste ji nakonfigurovali v konfiguraci služby SeaCat Auth.
- `<SEACAT_AUTH_PUBLIC_API_INTERNAL_URL>` je interní základní URL vaší veřejné API SeaCat Auth.

```nginx
location / {
	proxy_pass <PROTECTED_LOCATION_URL>;

	auth_request        /_cookie_introspect;
    auth_request_set    $authorization $upstream_http_authorization;
    proxy_set_header    Authorization $authorization;
    
    error_page 401 403 <SEACAT_AUTH_PUBLIC_API_URL>/openidconnect/authorize?response_type=code&scope=openid&client_id=signin&redirect_uri=<APP_DOMAIN>/auth/cookie_entry?grant_type=authorization_code;
}
```

- `<PROTECTED_LOCATION_URL>` je interní URL vašeho chráněného místa.
- `<SEACAT_AUTH_PUBLIC_API_URL>` je veřejné základní URL vaší veřejné API SeaCat Auth.