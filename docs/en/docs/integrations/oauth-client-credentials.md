---
title: OAuth 2.0 Client Credentials Flow
---

# OAuth 2.0 Client Credentials Flow

This flow is designed for **client applications** to **automatically** request short-lived access tokens. It follows the OAuth 2.0 specification for the Client Credentials Grant type.

> For long-lived, manually managed API keys, see [Client API Keys](./api-keys.md).

---

## Key Points

- Fully compliant with the OAuth 2.0 spec:  
  https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
- Token expiration is configurable but should be short (recommended: a few hours or less).  
- Default token expiration is 3 minutes. You can customize it in the config, for example:

```ini
[openidconnect]
client_credentials_grant_expiration=10m
````

---

## Client Setup Requirements

To enable client credentials flow for a client, ensure the following:

* The client has `seacatauth_credentials` enabled.
* The client has `token_endpoint_auth_method` enabled with a supported method (`client_secret_basic` or `client_secret_post`).
* The client has a valid `client_secret` configured.
* The client is assigned appropriate roles and/or tenants to control access privileges.

---

### Managing Client Attributes

Use the *Update Client* API to enable necessary attributes:

```http
PUT /client/{client_id}
Content-Type: application/json

{
  "seacatauth_credentials": true,
  "token_endpoint_auth_method": "client_secret_basic"
}
```

---

### Resetting the Client Secret

If you need to generate a new client secret, use the *Reset Client Secret* API:

```http
POST /client/{client_id}/reset_secret
```

---

### Assigning Access Privileges

Control the client’s API access by assigning tenants and roles to the credentials object:
`seacatauth:client:$CLIENT_ID`

---

## Requesting an Access Token

Clients request tokens by calling the OAuth 2.0 Token Endpoint with:

* Client credentials (sent via HTTP Basic Auth header or request body).
* `grant_type=client_credentials`
* Desired `scope` (e.g., tenant access).

### Example request using `curl`:

```bash
curl -X POST https://localhost:3081/openidconnect/token \
    -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data "grant_type=client_credentials&scope=tenant:my-corporation"
```

---

## Response

The response follows the OAuth 2.0 standard token response as described in [RFC6749 Section 5.1](https://datatracker.ietf.org/doc/html/rfc6749#section-5.1), including:

* `access_token`
* `token_type`
* `expires_in`
* (optionally) `scope`

---
