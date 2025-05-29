---
title: OAuth 2.0 Client credentials flow
---

# OAuth 2.0 Client credentials flow

- Used **by the client application** itself to **automatically** request short-lived access tokens. (For long-lived, manually managed API keys, see [Client API keys](./api-keys.md).)
- Complies with OAuth2 spec: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
- Token expiration is configurable, but it is recommended to use short expiration (a few hours at most). The default is 3 minutes.
```ini
[openidconnect]
client_credentials_grant_expiration=10m
```

## Setting up the client
- The client must:
    - have `seacatauth_credentials` enabled,
    - have `token_endpoint_auth_method` enabled (`client_secret_basic` or `client_secret_post`),
    - have a `client_secret` set,
    - have some roles and/or tenants assigned.
- Use the _Update client_ API to manage client attributes:
```
PUT /client/{client_id}
{"seacatauth_credentials": true, "token_endpoint_auth_method": "client_secret_basic"}
```
- Use the _Reset client secret_ API:
```
POST /client/{client_id}/reset_secret
```
- Set the access privileges of the client credentials (with ID `seacatauth:client:$CLIENT_ID`) by assigning them tenants and roles.

## Requesting the token
Make a request to the the OAuth 2.0 Token Endpoint that contains:
- your client credentials (in the Authorization header or in the request body),
- `grant_type=client_credentials`,
- desired `scope`.

Example:
```bash
curl -X POST https://localhost:3081/openidconnect/token \
    -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data "grant_type=client_credentials&scope=tenant:my-corporation"
```

The response complies with [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749#section-5.1).
