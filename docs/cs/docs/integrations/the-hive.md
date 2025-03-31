---
title: TheHive
---

# Připojení k TheHive

Toto je průvodce konfigurací [TheHive](https://thehive-project.org/) pro použití SeaCat Auth jako svého _Single Sign-on_ (SSO) poskytovatele OAuth2.


## Požadavky

- [Instalace SeaCat Auth s reverzním proxy a oběma webovými uživatelskými rozhraními.](../getting-started/quick-start)
- [TheHive](https://thehive-project.org/)


## Konfigurace

```hocon
auth {
    providers: [
        {name: session}
        {name: basic, realm: thehive}
        {name: local}
        {name: key}
        {
            name: oauth2
            clientId: "<CLIENT_ID>"
            clientSecret: "<CLIENT_SECRET>"
            redirectUri: "<THEHIVE_URL>/api/ssoLogin"
            responseType: "code"
            grantType: "authorization_code"
            authorizationUrl: "<PUBLIC_SEACAT_AUTH_API_URL>/openidconnect/authorize"
            authorizationHeader: "Bearer"
            tokenUrl: "<INTERNAL_SEACAT_AUTH_API_URL>/openidconnect/token"
            userUrl: "<INTERNAL_SEACAT_AUTH_API_URL>/openidconnect/userinfo"
            scope: ["openid"]
            userIdField: "email"
        }
    ]
}

user.autoCreateOnSso: true
```

- `<CLIENT_ID>` a `<CLIENT_SECRET>` jsou OAuth2 klientské přihlašovací údaje, které vám vydal SeaCat Auth.
- `<THEHIVE_URL>` je veřejná URL adresa, kde je The Hive dostupný.
- `<PUBLIC_SEACAT_AUTH_API_URL>` je veřejná (přístupná z prohlížeče uživatele) URL adresa veřejného kontejneru SeaCat Auth.
- `<INTERNAL_SEACAT_AUTH_API_URL>` je interní (přístupná z instance Hive) URL adresa veřejného kontejneru SeaCat Auth.

Další relevantní možnosti konfigurace naleznete v [dokumentaci The Hive](https://docs.thehive-project.org/thehive/installation-and-configuration/configuration/authentication/#oauth2).