---
title: OAuth 2.0 & OpenID Connect
---

# OAuth 2.0 v SeaCat Auth

Specifikace je k dispozici zde:
[https://tools.ietf.org/html/rfc6749](https://tools.ietf.org/html/rfc6749)


## Protokolové koncové body

- 3. Protokolové koncové body (autorizovací služba, autorizátor)
- 3.1. Autorizovací koncový bod (autorizovací služba, autorizátor)
- 3.2. Tokenový koncový bod (autorizovací služba, zpracovatel tokenů)
- 3.2.1. Autentizace klienta (autorizovací služba, autorizátor)

## Tok autorizace pomocí kódu

- 4.1.  Tok autorizace pomocí kódu (autorizovací služba, autorizátor)
- 4.1.1.  Žádost o autorizaci (autorizovací služba, autorizátor)
- 4.1.2.  Odpověď na autorizaci (autorizovací služba, autorizátor)
- 4.1.2.1.  Chybová odpověď (autorizovací služba, autorizátor)
- 4.1.3.  Žádost o přístupový token (autorizovací služba, zpracovatel tokenů)
- 4.1.4.  Odpověď na přístupový token (autorizovací služba, zpracovatel tokenů)

## Obnovení přístupového tokenu

- 6.  Obnovení přístupového tokenu (autorizovací služba, zpracovatel tokenů)

## Zrušení tokenu OAuth 2.0

[https://tools.ietf.org/html/rfc7009](https://tools.ietf.org/html/rfc7009)

# OpenID Connect v SeaCat Auth

Specifikace je k dispozici zde:
[https://openid.net/specs/openid-connect-core-1_0-23.html](https://openid.net/specs/openid-connect-core-1_0-23.html)

## Autentizace pomocí toku autorizace kódu

- 3.1.  Autentizace pomocí toku autorizace kódu (autorizovací služba, autorizátor)
- 3.1.1.  Kroky toku autorizace kódu (autorizovací služba, autorizátor)
- 3.1.2.  Autorizovací koncový bod (autorizovací služba, autorizátor)
- 3.1.2.1.  Žádost o autentizaci (autorizovací služba, autorizátor)
- 3.1.2.2.  Ověření žádosti o autentizaci (autorizovací služba, autorizátor)
- 3.1.2.3.  Autorizátor ověřuje koncového uživatele (autorizovací služba, autorizátor)
- 3.1.2.4.  Autorizátor získává souhlas/autorizaci koncového uživatele (autorizovací služba, autorizátor)
- 3.1.3.3.  Úspěšná odpověď na token (autorizovací služba, zpracovatel tokenů)
- 3.1.3.4.  Chybová odpověď na token (autorizovací služba, zpracovatel tokenů)
- 3.1.3.5.  Ověření odpovědi na token (autorizovací služba, zpracovatel tokenů)
- 3.1.3.6.  ID token (autorizovací služba, zpracovatel tokenů)

## UserInfo Endpoint

- 5.3.  UserInfo Endpoint (služba credentilasprovider, zpracovatel credentilasprovider)
- 5.3.1.  Žádost o UserInfo (služba credentilasprovider, zpracovatel credentilasprovider)
- 5.3.2.  Úspěšná odpověď na UserInfo (služba credentilasprovider, zpracovatel credentilasprovider)
- 5.3.3.  Chybová odpověď na UserInfo (služba credentilasprovider, zpracovatel credentilasprovider)

Správná struktura se všemi informacemi (například ověření informací o uživateli) musí být implementována v budoucnu.

## Nastavení OpenID Connect v WebUI

Výchozí cesta pro službu OpenID connect je `openidconnect`. OpenID connect (`oidc`) může také obsahovat externí URL OpenID connect. V takovém případě je URL přepsána pomocí URL v parametru `oidc`. Externí URL OpenID connect musí začínat na `http://` nebo `https://`

Pro podrobnosti o konfiguraci se prosím odkažte na [TeskaLabs Wiki](http://wiki.teskalabs.int/rd/projects/asab-webui/configuration/url-config)

# JWT token

[https://connect2id.com/learn/openid-connect](https://connect2id.com/learn/openid-connect)