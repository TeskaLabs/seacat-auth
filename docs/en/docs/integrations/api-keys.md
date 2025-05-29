---
title: API keys
---

# API keys

- API keys are long-lived tokens, **manually** requested and managed by **the admin (superuser)**. For app-managed short-lived tokens, see [OAuth 2.0 client credentials flow](./oauth-client-credentials.md).
- The admin can issue new API keys, list existing ones and revoke them.

## Pre-requisites
- This API requires **superuser** privileges.
- The target client must:
    - have `seacatauth_credentials` enabled.
- Use the _Update client_ API to update client attributes:
```
PUT /client/{client_id}
{"seacatauth_credentials": true}
```
- Set the access privileges of the client credentials (with ID `seacatauth:client:$CLIENT_ID`) by assigning them tenants and roles.


## Issue a new API key
- `POST /client/{client_id}/token`
- JSON body parameters:
    - `exp` (optional): The expiration time or ISO timestamp of the token, e.g. `180d` for 180 days from now, or `2030-01-01` for that exact date.
    - `tenant` (optional): The tenant to which the token will grant access. If not specified, the token is tenantless.
    - `label` (optional): Label for the API key, useful for identification.

Example:
```
POST /client/{client_id}/token
{"expiration": "365d", "tenant": "acme-corp", "label": "API key for my monitoring application"}
```

Successful response contains:
- Access token value `token` (used as a Bearer token for API access), 
- token identifier `_id` (used for managing and invalidating the token),
- token expiration timestamp `exp` in ISO format, and
- token `resources` object.

## Use the API key
The received access token value is used exactly the same way as any other OAuth 2.0 Access Token is used, i.e. in the HTTP Authorization header with the `Bearer` keyword.

```bash
curl -X GET "http://localhost/api/items" -H "Authorization: Bearer ${API_KEY}`
```

## Revoke API key
Use the received token ID to invalidate the token.
```
DELETE /client/{client_id}/token/{token_id}
```

## Revoke all API keys
```
DELETE /client/{client_id}/token
```
