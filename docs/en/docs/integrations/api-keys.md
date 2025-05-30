---
title: API Keys Management
---

# API Keys Management Guide

This guide explains how to manage **API keys** in the authentication server. API keys are long-lived tokens issued and controlled manually by administrators with superuser privileges.

> For short-lived tokens managed by applications, refer to the [OAuth 2.0 Client Credentials Flow](./oauth-client-credentials.md).

---

## Overview

- API keys are **long-lived access tokens** used to authenticate API requests.
- Only **admins (superusers)** can create, list, and revoke API keys.
- API keys grant access to specific tenants and roles, allowing fine-grained permission control.

---

## Prerequisites

To manage API keys, ensure the following:

- You have **superuser** privileges.
- There is a registered Client with the attribute `seacatauth_credentials` enabled.
- To enable this attribute on an existing client, use the _Update Client_ API:

```http
PUT /client/{client_id}
Content-Type: application/json

{
  "seacatauth_credentials": true
}
```

* Enabling `seacatauth_credentials` creates a credentials object identified by:
  `seacatauth:client:$CLIENT_ID`

* You can control the privileges of API keys by assigning tenants and roles to this credentials object.

---

## Creating a New API Key

To issue a new API key, send a POST request to:

```http
POST /client/{client_id}/token
Content-Type: application/json
```

### Request body parameters (all optional):

| Parameter | Description                                                                                           | Example                    |
| --------- | ----------------------------------------------------------------------------------------------------- | -------------------------- |
| `exp`     | Expiration time of the API key. Can be a duration (e.g., `180d`) or an exact ISO date (`2030-01-01`). | `"365d"` or `"2030-01-01"` |
| `tenant`  | Tenant the API key grants access to. If omitted, the token is tenantless.                             | `"acme-corp"`              |
| `label`   | A descriptive label for easier identification of the API key.                                         | `"Monitoring app key"`     |

### Example:

```json
{
  "exp": "365d",
  "tenant": "acme-corp",
  "label": "API key for my monitoring application"
}
```

### Successful response includes:

* `token` — The API key value (use as Bearer token for API calls).
* `_id` — Token identifier (used for managing and revoking the key).
* `exp` — Token expiration timestamp in ISO format.
* `resources` — Access scope granted by the token.

---

## Using the API Key

Use the API key value as a Bearer token in the HTTP Authorization header for your API requests:

```bash
curl -X GET "http://localhost/api/items" -H "Authorization: Bearer ${API_KEY}"
```

---

## Revoking an API Key

To revoke a specific API key, use its token ID in the DELETE request:

```http
DELETE /client/{client_id}/token/{token_id}
```

---

## Revoking All API Keys for a Client

To revoke **all** API keys issued to a client:

```http
DELETE /client/{client_id}/token
```
