---
title: TheHive
---

# Connecting to TheHive

This is a guide to configuring [TheHive](https://thehive-project.org/) to use SeaCat Auth as its _Single Sign-on_ (SSO) OAuth2 provider.


## Prerequisites

- [Installation of SeaCat Auth with a reverse proxy and both web UIs.](../getting-started/quick-start)
- [TheHive](https://thehive-project.org/)


## Configuration

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

- `<CLIENT_ID>` and `<CLIENT_SECRET>` is the OAuth2 Client credentials issued to you by SeaCat Auth.
- `<THEHIVE_URL>` is the public URL where The Hive is available.
- `<PUBLIC_SEACAT_AUTH_API_URL>` is the public (accessible from the user browser) URL of SeaCat Auth public container.
- `<INTERNAL_SEACAT_AUTH_API_URL>` is the internal (accessible from the Hive instance) URL of SeaCat Auth public container.

Further relevant configuration options can be found in [The Hive documentation](https://docs.thehive-project.org/thehive/installation-and-configuration/configuration/authentication/#oauth2).
