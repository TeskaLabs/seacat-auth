---
title: Klienti
---

# Klienti

Klient je entita, která využívá autentizační a autorizační služby poskytované autorizačním serverem. 
Tato autorizace umožňuje Klientovi přístup k chráněným zdrojům.
V běžném scénáři je Klient webová aplikace a Vlastník zdroje je backendová aplikace 
umístěná na vzdáleném serveru.

Než Klient může požádat o autorizaci, musí se zaregistrovat na autorizačním serveru a získat jedinečné ID.
Registraci lze provést buď v Admin UI, nebo prostřednictvím Admin API.

## Metadata klienta

Aktuální seznam metadat klienta podporovaných Seacat Auth lze získat pomocí API `GET /client/features`.

### Kanonická metadata OAuth 2.0 a OpenID Connect

Definováno v [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
a [OAuth 2.0 Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591#section-2).

#### `client_id`
`NENÍ EDITOVATELNÉ` Jedinečné ID Klienta. Ve výchozím nastavení je to neprůhledný řetězec generovaný autorizačním serverem.
Je možné požádat o vlastní ID poskytnutím nekanonického parametru `preferred_client_id` v 
žádosti o registraci klienta.
ID není možné upravit, jakmile je klient již registrován.

#### `client_name`
`POŽADOVÁNO` Lidsky čitelný název Klienta, který bude předložen koncovému uživateli.

#### `client_secret`
Tajný řetězec klienta OAuth 2.0. Tato hodnota je používána důvěrnými klienty k autentizaci na koncovém bodě tokenu.
Je generována autorizačním serverem a není přímo editovatelná.

#### `client_uri`
URL domovské stránky Klienta.

#### `redirect_uris`
`POŽADOVÁNO` Pole hodnot URI pro přesměrování používané Klientem.

#### `application_type`
Typ aplikace. Výchozí hodnota, pokud je vynecháno, je `web`.

Podporované možnosti: `web`

#### `response_types`
JSON pole obsahující seznam hodnot response_type OAuth 2.0, které Klient deklaruje, že se omezí 
na používání. Pokud je vynecháno, výchozí hodnota je, že Klient použije pouze Response Type `code`.

Podporované možnosti: `code`

#### `grant_types`
JSON pole obsahující seznam Grant Types OAuth 2.0, které Klient deklaruje, že se omezí 
na používání. Pokud je vynecháno, výchozí hodnota je, že Klient použije pouze Grant Type `authorization_code`.

Podporované možnosti: `authorization_code`

#### `token_endpoint_auth_method`
Požadovaná metoda autentizace Klienta pro koncový bod tokenu. Pokud je vynecháno, výchozí hodnota je `none`.

Podporované možnosti: `none`

#### `code_challenge_method`
Metoda výzvy kódu (používá se v [Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)) 
kterou se Klient omezí na používání na koncovém bodě autorizace. Výchozí hodnota, pokud je vynecháno, je `none`.

Podporované možnosti: 

- `none`: PKCE je zakázáno.
- `plain`: Výzva kódu je stejná jako ověřovatel kódu.
- `S256`: Výzva kódu je odvozena od ověřovatele kódu pomocí hashovacího algoritmu SHA-256.

## Nekanonic metadata

Toto jsou specifické funkce pro Seacat-Auth.

#### `preferred_client_id`
`POUZE REGISTRACE` Požaduje konkrétní `client_id` místo náhodně generovaného při registraci klienta.

#### `redirect_uri_validation_method`
Specifikuje metodu, jakým je validováno URI pro přesměrování používané v autorizačních požadavcích. Výchozí a doporučená 
hodnota je `full_match`.

Podporované možnosti: 

- `full_match`: **Jediná možnost vyhovující OAuth2.0.** Požadované URI pro přesměrování musí přesně odpovídat jednomu z registrovaných
  URI pro přesměrování.
- `prefix_match`: Požadované URI pro přesměrování musí začínat jedním z registrovaných URI pro přesměrování a jejich hostname musí 
  přesně odpovídat.
- `none`: Neprovádí se žádná validace URI pro přesměrování. Není bezpečné.

#### `cookie_name`
`NENÍ EDITOVATELNÉ` Jedinečný název cookie odvozený z ID Klienta autorizačním serverem. Cookie s tímto názvem uchovává 
informace 

#### `cookie_webhook_uri`
Webhook URI pro nastavení dalších vlastních cookies na vstupním bodu cookie. Musí to být back-channel URI a musí 
přijímat JSON PUT požadavek a odpovídat JSON objektem cookies k nastavení.

#### `cookie_entry_uri`
Veřejné URI vstupního bodu cookie klienta. Toto pole je **povinné** pro autorizaci založenou na cookies (včetně 
autorizace batman). Takový vstupní bod by měl být dostupný na každém hostname, kde jsou Klienti, kteří používají 
autorizaci založenou na cookies.

#### `cookie_domain`
Doména cookie klienta. Pokud není specifikováno, použije se výchozí doména cookie aplikace.

#### `authorize_uri`
URL koncového bodu autorizace OAuth. Užitečné při přihlašování z jiného než výchozího doménového jména.

#### `login_uri`
URL preferované přihlašovací stránky. Užitečné při přihlašování z jiného než výchozího doménového jména.

#### `authorize_anonymous_users`
Boolean hodnota specifikující, zda autorizovat požadavky s anonymními uživateli.

#### `anonymous_cid`
ID přihlašovacích údajů, které se používá pro autentizaci anonymních relací.

#### `session_expiration`
Vypršení relace klienta. Hodnota může být buď počet sekund, nebo řetězec časové jednotky, jako je `4 h` nebo `3 d`.