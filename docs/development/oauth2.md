---
title: OAuth 2.0
---

# OAuth 2.0 in SeaCat Auth

The specification is available here:
[https://tools.ietf.org/html/rfc6749](https://tools.ietf.org/html/rfc6749)


## Protocol Endpoints

- 3. Protocol Endpoints (authorization service, authorization handler)
- 3.1. Authorization Endpoint (authorization service, authorization handler)
- 3.2. Token Endpoint (authorization service, token handler)
- 3.2.1. Client Authentication (authorization service, authorization handler)

## Authorization Code Grant flow

- 4.1.  Authorization Code Grant (authorization service, authorization handler)
- 4.1.1.  Authorization Request (authorization service, authorization handler)
- 4.1.2.  Authorization Response (authorization service, authorization handler)
- 4.1.2.1.  Error Response (authorization service, authorization handler)
- 4.1.3.  Access Token Request (authorization service, token handler)
- 4.1.4.  Access Token Response (authorization service, token handler)

##  Refreshing an Access Token

- 6.  Refreshing an Access Token (authorization service, token handler)

## OAuth 2.0 Token Revocation

[https://tools.ietf.org/html/rfc7009](https://tools.ietf.org/html/rfc7009)

# OpenID Connect in SeaCat Auth

The specification is available here:
[https://openid.net/specs/openid-connect-core-1_0-23.html](https://openid.net/specs/openid-connect-core-1_0-23.html)

## Authentication using the Authorization Code Flow

- 3.1.  Authentication using the Authorization Code Flow (authorization service, authorization handler)
- 3.1.1.  Authorization Code Flow Steps (authorization service, authorization handler)
- 3.1.2.  Authorization Endpoint (authorization service, authorization handler)
- 3.1.2.1.  Authentication Request (authorization service, authorization handler)
- 3.1.2.2.  Authentication Request Validation (authorization service, authorization handler)
- 3.1.2.3.  Authorization Server Authenticates End-User (authorization service, authorization handler)
- 3.1.2.4.  Authorization Server Obtains End-User Consent/Authorization (authorization service, authorization handler)edentials policy
      url: /config/credentials/policy
    - title: Credentials providers
      url: /config/credentials/providers
    - title: Provisioning
      url: /config/provisioning
    - title: External login
      url: /config/external-login
    - title: Bouncer
      url: /config/bouncer
    - title: Cookies
      url: /config/cookies
    - title: LDAP
      url: /config/ldap
    - title: E-mail server
      url: /config/mail-server
    - title: Deployment with Docker
      url: /config/docker

  - title: Reference
- 3.1.3.3.  Successful Token Response (authorization service, token handler)
- 3.1.3.4.  Token Error Response (authorization service, token handler)
- 3.1.3.5.  Token Response Validation (authorization service, token handler)
- 3.1.3.6.  ID Token (authorization service, token handler)

## UserInfo Endpoint

- 5.3.  UserInfo Endpoint (credentilasprovider service, credentilasprovider handler)
- 5.3.1.  UserInfo Request (credentilasprovider service, credentilasprovider handler)
- 5.3.2.  Successful UserInfo Response (credentilasprovider service, credentilasprovider handler)
- 5.3.3.  UserInfo Error Response (credentilasprovider service, credentilasprovider handler)

The proper structure with all information (such as validation of user info) must be implemented in the future.

## Set OpenID Connect in WebUI

Default path for OpenID connect service is `openidconnect`. OpenID connect (`oidc`) can also hold an external OpenID connect URL. In that case, URL is rewritten with URL in `oidc` parameter. External OpenID connect URL must start with `http://` or `https://`

For configuration details, please refer to [TeskaLabs Wiki](http://wiki.teskalabs.int/rd/projects/asab-webui/configuration/url-config)

# JWT token

[https://connect2id.com/learn/openid-connect](https://connect2id.com/learn/openid-connect)

