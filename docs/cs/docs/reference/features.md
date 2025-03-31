---
title: Funkce
---

# Hlavní funkce TeskaLabs SeaCat Auth

## Autentizace

  * Dvoufaktorová autentizace (2FA) / Vícefaktorová autentizace (MFA)
  * Podporované faktory:
    * Heslo
    * [Časově založené jednorázové heslo](https://en.wikipedia.org/wiki/Time-based_One-Time_Password) (TOTP)
    * SMS kód
    * [FIDO2](https://en.wikipedia.org/wiki/FIDO2_Project) / [WebAuthn](https://en.wikipedia.org/wiki/WebAuthn)
      * [YubiKey](https://www.yubico.com)
      * Idem Key
      * Android telefon
      * Apple TouchID / FaceID
      * Další autentifikátory / klíče
    * Podsíť (ROADMAP 🗺️)
    * Hlavička požadavku (X-Header)
  * Autentizace mezi stroji
    * API klíče (ROADMAP 🗺️)
  * Šifrování od konce k konci v přihlašovacích relacích

## Autorizace
  * [Kontrola přístupu na základě rolí](https://en.wikipedia.org/wiki/Role-based_access_control) (RBAC)
    * Role
    * Zdroje
  * Politiky (ROADMAP 🗺️)
  * [Kontrola přístupu na základě atributů](https://en.wikipedia.org/wiki/Attribute-based_access_control) (ABAC) (ROADMAP 🗺️)


## Správa identit
  * Federace uživatelských identit (aka _ověření_)
  * Dostupní poskytovatelé identit:
    * [LDAP](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol) a [Microsoft Active Directory](https://en.wikipedia.org/wiki/Active_Directory)
    * [Google](https://google.com/)
    * [MongoDB](https://www.mongodb.com)
    * Soubor ([htpasswd](https://httpd.apache.org/docs/2.4/programs/htpasswd.html))
    * Slovník v paměti
    * [ElasticSearch](https://www.elastic.co)
    * MySQL
    * Vlastní poskytovatel identit (třída Python 3)

## Obecné

* [Víceuživatelský režim](https://en.wikipedia.org/wiki/Multitenancy) včetně správy nájemců pro další služby a aplikace
* Správa relací
* [Jednotné přihlášení](https://en.wikipedia.org/wiki/Single_sign-on)
* [OpenId Connect](https://openid.net/connect/) / [OAuth2](https://oauth.net/2/)
* Backend pro introspekci autorizace/autentizace pro [NGINX](https://nginx.org)
* Interceptor autorizace/autentizace pro aplikace třetích stran (aka "Batman")
  * Kibana &amp; ElasticSearch
  * [Grafana](https://grafana.com)
  * Docker registry / NGINX (ROADMAP 🗺️)
  * HTTP [Základní autentizace](https://en.wikipedia.org/wiki/Basic_access_authentication)
* Mód provisioning
* Strukturované logování přes [Syslog 5424](https://datatracker.ietf.org/doc/html/rfc5424)
* Auditní stopa
* Telemetrie
  * [InfluxDB](https://www.influxdata.com)
  * [Prometheus](https://prometheus.io) / [OpenMetrics](https://openmetrics.io)


# Uživatelské rozhraní
* Plná lokalizace / internacionalizace

## [Webové uživatelské rozhraní pro uživatele](../webui/seacat-auth)
* Přihlášení
* Registrace nových uživatelů
* Portál pro vlastní správu

## [Webové uživatelské rozhraní pro administrátory](../webui/seacat)
* Správa ověření
* Správa nájemců
* Správa RBAC
* Správa relací