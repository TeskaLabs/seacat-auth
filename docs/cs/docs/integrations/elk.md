---
title: Elasticsearch a Kibana
---

# Připojení k Elasticsearch a Kibana

Toto je průvodce konfigurací SeaCat Auth jako proxy pro uživatele a role [Kibana](https://www.elastic.co/kibana/).
Protože Kibana není kompatibilní s OAuth a podporuje pouze základní autentizaci, 
je integrace do prostředí Single Sign-On vyžaduje zvláštní přístup.
Komponenta **SeaCat Auth Batman** (Basic Auth Token MANager) je navržena přesně pro tento úkol -
"překládá" Seacat session cookies na základní autentizační hlavičky a
synchronizuje uživatele Kibana/Elasticsearch s přihlašovacími údaji SeaCat Auth a jejich přístupovými právy.


## Jak to funguje?

Tok pro použití Batman auth je téměř stejný jako [tok cookie auth](index#cookie-authorization-flow), 
jediným rozdílem je typ introspekce, který se používá. 
Místo koncového bodu `PUT /nginx/introspect/cookie` (který vyměňuje Seacat klientské cookie za ID token), 
Batman auth používá `PUT /nginx/introspect/batman` (který vyměňuje Seacat klientské cookie za základní autentizační hlavičku).


## Příklad konfigurace

Nastavme autorizaci Seacat Batman pro naši aplikaci Kibana. Musíme mít 
aplikace [Elasticsearch](https://www.elastic.co/elasticsearch/) a [Kibana](https://www.elastic.co/kibana/) 
spuštěné, stejně jako [funkční instanci SeaCat Auth s Nginx reverzní proxy](../getting-started/quick-start). 
Budeme muset nakonfigurovat tyto tři komponenty:

- Aktualizovat **konfiguraci SeaCat Auth** o sekci `[batman:elk]`, aby mohla používat Elasticsearch API pro synchronizaci 
  uživatelů a správu jejich autorizace.
- Vytvořit a nakonfigurovat **Kibana klienta**. Tento objekt klienta reprezentuje a identifikuje Kibana 
  v komunikaci se SeaCat Auth.
- Připravit potřebné **serverové lokace** v konfiguraci Nginx.

### Konfigurace SeaCat Auth

Vytvořte sekci ELK Batman a zadejte základní URL Elasticsearch a API přihlašovací údaje, např.

```ini
[batman:elk]
url=http://localhost:9200
username=admin
password=elasticpassword
```

### Konfigurace klienta

Použijte API klienta SeaCat Auth (nebo Seacat Admin UI) k registraci Kibana jako klienta. 
Tělo požadavku musí obsahovat čitelný `client_name`, pole `redirect_uris` obsahující URL webového rozhraní Kibana 
a `cookie_entry_uri` pro vaše hostname (tuto lokaci definujeme v konfiguraci Nginx níže).
Doporučujeme také nastavit `redirect_uri_validation_method` na `prefix_match`, pokud chcete povolit okamžité přesměrování 
na podcesty Kibana.
V našem případě můžeme poslat následující požadavek (nezapomeňte použít vaše skutečné hostname místo `example.com`!):

```
POST /client
{
	"client_name": "Kibana",
	"redirect_uri_validation_method": "prefix_match",
	"redirect_uris": [
		"https://example.com/kibana"
	],
	"cookie_entry_uri": "https://example.com/seacat_auth/cookie"
}
```

Server odpoví s ID přiděleným našemu klientovi a dalšími atributy:

```
{
	"client_id": "RZhlE-D4yuJxoKitYVL4dg",
	"client_id_issued_at": 1687170414,
	"application_type": "web",
	...,
	"cookie_name": "SeaCatSCI_QLFLEAU4D726UPA3"
}
```

V dalším kroku použijeme `client_id` a `client_cookie`.

### Konfigurace Nginx

Minimální konfigurace vyžaduje definici následujících tří lokalit v nginx:

- **Lokalita klientské stránky:** Ochráněná veřejná lokalita s webovou aplikací Kibana.
- **Introspekce klienta:** Interní koncový bod používaný direktivou nginx `auth_request`.
- **Vstupní bod pro cookies klienta:** Veřejný koncový bod, který vydává Seacat klientské cookie na konci úspěšného 
  toku autorizace.

#### Lokalita klientské stránky

```nginx
location /kibana/ {
	# Kibana upstream
	proxy_pass http://kibana_api;

	# Auth introspekční koncový bod
	auth_request /_kibana_introspection;

	# Předat Batman hlavičku získanou z introspekce SeaCat Auth do Kibana
	auth_request_set $auth_header $upstream_http_authorization;
	proxy_set_header Authorization $auth_header;

	# V případě, že introspekce zjistí neplatnou autorizaci, přesměrovat na OAuth autorizační koncový bod
	# !! Použijte skutečné client_id vašeho klienta a skutečné hostname vašeho webu !!
	error_page 401 https://example.com/auth/api/openidconnect/authorize?response_type=code&scope=cookie%20batman&client_id=RZhlE-D4yuJxoKitYVL4dg&redirect_uri=https://example.com$request_uri;

	# Hlavičky požadované Kibana
	proxy_http_version 1.1;
	proxy_set_header Upgrade $http_upgrade;
	proxy_set_header Connection 'upgrade';
	proxy_set_header Host $host;
	proxy_cache_bypass $http_upgrade;
}
```

#### Introspekce klienta

```nginx
location = /_kibana_introspection {
	internal;

	# Seacat Auth Batman introspekční upstream
	# !! Použijte skutečné client_id vašeho klienta !!
	proxy_method          POST;
	proxy_pass            http://seacat_auth_api/nginx/introspect/batman?client_id=RZhlE-D4yuJxoKitYVL4dg;

	proxy_set_header      X-Request-URI "$request_uri";
	proxy_ignore_headers  Cache-Control Expires Set-Cookie;

	# Cache odpovědi introspekce
	proxy_buffer_size     128k;
	proxy_buffers         4 256k;
	proxy_busy_buffers_size  256k;
	proxy_cache           kibana_auth;
	# !! Vyplňte skutečné cookie_name vašeho klienta !!
	proxy_cache_key       $cookie_SeaCatSCI_QLFLEAU4D726UPA3;
	proxy_cache_lock      on;
	proxy_cache_valid     200 10s;
}
```

#### Vstupní bod pro cookies

Musí být umístěn na stejném hostname jako chráněná lokalita klienta. 
Měl by být vystaven jeden vstupní bod pro cookies na hostname, sdílený všemi klienty založenými na cookies na tomto hostname.

```nginx
location = /seacat_auth/cookie {
	# Seacat Auth cookie vstupní upstream
	proxy_method          POST;
	proxy_pass            http://seacat_auth_api/cookie/entry;

	# Přenést OAuth autorizační kód z dotazu do těla požadavku
	# !! Použijte skutečné client_id vašeho klienta !!
	proxy_set_header      Content-Type "application/x-www-form-urlencoded";
	proxy_set_body        $args;
}
```