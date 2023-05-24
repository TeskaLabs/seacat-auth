---
title: Main features of TeskaLabs SeaCat Auth
---

# Main features of TeskaLabs SeaCat Auth

## Authentication

  * Second-factor Authentication (2FA) / Multi-factor Authentication (MFA)
  * Supported factors:
    * Password
    * [Time-based One-Time Password](https://en.wikipedia.org/wiki/Time-based_One-Time_Password) (TOTP)
    * SMS code
    * [FIDO2](https://en.wikipedia.org/wiki/FIDO2_Project) / [WebAuthn](https://en.wikipedia.org/wiki/WebAuthn)
      * [YubiKey](https://www.yubico.com)
      * Idem Key
      * Android phone
      * Apple TouchID / FaceID
      * Other authenticators / keys
    * Subnet (ROADMAP 🗺️)
    * Request header (X-Header)
  * Machine-to-Machine Authentication
    * API keys (ROADMAP 🗺️)
  * End-to-End encryption in login sessions

## Authorization
  * [Role-based access control](https://en.wikipedia.org/wiki/Role-based_access_control) (RBAC)
    * Roles
    * Resources
  * Policies (ROADMAP 🗺️)
  * [Attribute-based access control](https://en.wikipedia.org/wiki/Attribute-based_access_control) (ABAC) (ROADMAP 🗺️)


## Identity management
  * Federation of user identities (aka _credentials_)
  * Available identity providers:
    * [LDAP](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol) and [Microsoft Active Directory](https://en.wikipedia.org/wiki/Active_Directory)
    * [Google](https://google.com/)
    * [MongoDB](https://www.mongodb.com)
    * File ([htpasswd](https://httpd.apache.org/docs/2.4/programs/htpasswd.html))
    * In-memory dictionary
    * [ElasticSearch](https://www.elastic.co)
    * MySQL
    * Custom identity provider (Python 3 class)

## General

* [Multitenancy](https://en.wikipedia.org/wiki/Multitenancy) including tenant management for other services and applications
* Session management
* [Single-sign on](https://en.wikipedia.org/wiki/Single_sign-on)
* [OpenId Connect](https://openid.net/connect/) / [OAuth2](https://oauth.net/2/)
* Authorization/authentication introspection backend for [NGINX](https://nginx.org)
* Authorization/authentication interceptor for 3rd party applications (aka "Batman")
  * Kibana &amp; ElasticSearch
  * [Grafana](https://grafana.com)
  * Docker registry / NGINX (ROADMAP 🗺️)
  * HTTP [Basic Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication)
* Provisioning mode
* Structured logging over [Syslog 5424](https://datatracker.ietf.org/doc/html/rfc5424)
* Audit trail
* Telemetry
  * [InfluxDB](https://www.influxdata.com)
  * [Prometheus](https://prometheus.io) / [OpenMetrics](https://openmetrics.io)


# User interface
* Full localization / internationalization

## [Web User Interface for users](../webui/seacat-auth)
* Login
* Registration of new users
* Self-care portal

## [Web User Interface for administrators](../webui/seacat)
* Credentials administrations
* Tenant management
* RBAC management
* Session management
