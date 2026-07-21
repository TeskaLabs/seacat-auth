# Audit Logging Improvement Plan for SeaCat Auth

This document inventories all current `AuditLogger` usage, identifies missing audit events, flags system logs (`L.log`, `L.error`, etc.) that should be audit events, and analyzes the consistency of log messages and `struct_data` attributes. It is intended as a planning artifact for improving SeaCat Auth's audit logging.

---

## 1. Executive Summary

- `AuditLogger` is defined as a plain Python `logging.Logger` named `"AUDIT"` in `seacatauth/__init__.py`.
- It is used in **15 files** with **60 call sites**.
- Coverage is good for interactive login, OAuth token/authorization flows, credentials CRUD, password changes, and impersonation.
- Significant gaps exist for: session lifecycle, role/tenant/resource mutations, MFA/WebAuthn/external-login changes, API key lifecycle, and many authentication/authorization failure paths that are currently logged only to the module system logger (`L`).
- Several inconsistencies exist in message style, punctuation, and `struct_data` keys, and at least one security concern (raw password reset token logged in `struct_data`) was found.
- ASAB `Request`, `Authz`, and `Tenant` context variables can be used to automatically enrich every audit entry with `from_ip`, `agent_cid`, `agent_sid`, `tenant`, and `superuser` status via a small helper, reducing repetition and manual `by_cid`, `from_ip`, and request argument drilling.

---

## 2. AuditLogger Definition and Pattern

### 2.1 Definition

```python:257:257:seacatauth/__init__.py
AuditLogger = logging.getLogger("AUDIT")
```

`AuditLogger` is **not** a custom wrapper class. It is a standard Python logger retrieved by name, enabling routing to a dedicated audit sink via the ASAB logging configuration. It is imported in submodules as `from .. import AuditLogger` (or `from ... import AuditLogger` in nested packages).

### 2.2 Logger `L` (system/operational log)

Most modules define their own operational logger:

```python
import logging
L = logging.getLogger(__name__)
```

This is used for debugging, error tracing, and operational diagnostics. The distinction between `L` and `AuditLogger` should be: **security-relevant events that need non-repudiation, compliance, or forensic review go to `AuditLogger`**; everything else stays on `L`.

### 2.3 Typical call pattern

The established pattern is:

```python
AuditLogger.log(asab.LOG_NOTICE, "Event description", struct_data={
    "cid": credentials_id,
    "sid": session_id,
    "from_ip": access_ips,
    # ...
})
```

`asab.LOG_NOTICE` is used for 57 of the 60 calls. The remaining three are in `authn/handler/account.py` where impersonation failures use `AuditLogger.warning()` and `AuditLogger.exception()`.

---

## 3. Current AuditLogger Usage Inventory

### 3.1 Summary Statistics

| Metric | Value |
|---|---|
| Definition | `seacatauth/__init__.py:257` |
| Files importing AuditLogger | 15 |
| Total call sites | 60 |
| `AuditLogger.log(asab.LOG_NOTICE, ...)` | 57 |
| `AuditLogger.warning(...)` | 2 |
| `AuditLogger.exception(...)` | 1 |

### 3.2 Files with AuditLogger

| File | Domain |
|---|---|
| `seacatauth/authn/service.py` | Authentication orchestration |
| `seacatauth/authn/m2m.py` | Machine-to-machine authentication |
| `seacatauth/authn/handler/public.py` | Public login/logout endpoints |
| `seacatauth/authn/handler/account.py` | Impersonation |
| `seacatauth/external_login/authentication/service.py` | External login completion |
| `seacatauth/cookie/service.py` | Anonymous cookie session creation |
| `seacatauth/cookie/handler.py` | Cookie bouncer introspection |
| `seacatauth/openidconnect/service.py` | Client credentials token issuance |
| `seacatauth/openidconnect/handler/token.py` | Token endpoint |
| `seacatauth/openidconnect/handler/authorize.py` | Authorization endpoint |
| `seacatauth/openidconnect/handler/session.py` | OIDC session logout |
| `seacatauth/credentials/service.py` | Credentials CRUD |
| `seacatauth/credentials/registration/service.py` | Invitations/registration |
| `seacatauth/credentials/change_password/handler.py` | Password change/reset |
| `seacatauth/client/service.py` | Client secret rotation |

### 3.3 Detailed Usage by Domain

#### Authentication

| File | Line | Message | Key `struct_data` | Notes |
|---|---|---|---|---|
| `authn/handler/public.py` | 189 | `Authentication failed` | `cid`, `lsid`, `ident`, `from_ip` | Failed encrypted login |
| `authn/handler/public.py` | 299 | `Logout successful` | `cid`, `sid`, `token_type: "cookie"` | Cookie logout |
| `authn/service.py` | 360 | `Authentication successful` | `cid`, `lsid`, `sid`, `from_ip` | Root SSO session created/updated |
| `authn/m2m.py` | 98 | `Authentication successful` | `cid`, `sid`, `fi`, `m2m: True` | M2M basic auth success |
| `authn/m2m.py` | 106 | `Authentication failed` | `cid`, `fi`, `m2m: True` | M2M basic auth failure |
| `external_login/authentication/service.py` | 672 | `Authentication successful` | `cid`, `lsid: "<external-login>"`, `sid`, `from_ip`, `authn_by` | External login success |
| `cookie/service.py` | 209 | `Authentication successful` | `anonymous: True`, `cid`, `client_id`, `track_id`, `fi` | Anonymous cookie session |

#### Impersonation

| File | Line | Message | Key `struct_data` | Level |
|---|---|---|---|---|
| `authn/handler/account.py` | 170 | `Impersonation failed: Target credentials ID not found` | `impersonator_cid`, `impersonator_sid`, `target_cid`, `from_ip` | `warning` |
| `authn/handler/account.py` | 178 | `Impersonation failed: Access denied` | same | `warning` |
| `authn/handler/account.py` | 186 | `Impersonation failed: Unexpected error ({e})` | same | `exception` |
| `authn/handler/account.py` | 194 | `Impersonation successful` | `impersonator_cid`, `impersonator_sid`, `target_cid`, `target_sid`, `from_ip` | `LOG_NOTICE` |

#### Logout

| File | Line | Message | Key `struct_data` |
|---|---|---|---|
| `openidconnect/handler/session.py` | 71 | `Logout successful` | `cid`, `sid`, `psid`, `token_type: "access_token"` |

#### OAuth Authorization

| File | Line | Message | Key `struct_data` |
|---|---|---|---|
| `openidconnect/handler/authorize.py` | 619 | `Authorization successful` | `psid`, `sid`, `cid`, `t`, `client_id`, `anonymous`, `from_ip`, `scope` |
| `openidconnect/handler/authorize.py` | 939 | `Authorization failed` | `e` (error code), `cid`, `client_id`, `**error.StructData` | Called from 6 catch sites (lines 202, 205, 211, 244, 247, 253). Error `StructData` may include `reason`, `scope`, `redirect_uri`. |

#### OAuth Token Endpoint

| File | Line | Message | Notes |
|---|---|---|---|
| `openidconnect/handler/token.py` | 101 | `Token request denied: Unauthorized client.` |  |
| `openidconnect/handler/token.py` | 117 | `Token request denied: Unsupported grant type.` |  |
| `openidconnect/handler/token.py` | 128 | `Token request denied: Unauthorized client.` | Client auth error in grant handler |
| `openidconnect/handler/token.py` | 136 | `Token request denied: Invalid client.` |  |
| `openidconnect/handler/token.py` | 144 | `Token request denied: Invalid scope.` |  |
| `openidconnect/handler/token.py` | 169 | `Token request denied: Invalid or expired authorization code.` |  |
| `openidconnect/handler/token.py` | 182 | `Token request denied: Code challenge failed.` |  |
| `openidconnect/handler/token.py` | 195 | `Token request denied: Redirect URI mismatch.` |  |
| `openidconnect/handler/token.py` | 204 | `Token request denied: Invalid request.` |  |
| `openidconnect/handler/token.py` | 220 | `Token request granted.` |  |
| `openidconnect/handler/token.py` | 266 | `Token request denied: Invalid or expired refresh token.` |  |
| `openidconnect/handler/token.py` | 278 | `Token request denied: Cannot verify client.` |  |
| `openidconnect/handler/token.py` | 296 | `Token request granted.` |  |
| `openidconnect/handler/token.py` | 328 | `Token request denied: Missing scope parameter.` |  |
| `openidconnect/handler/token.py` | 348 | `Token request denied: Client does not have Seacat Auth credentials enabled.` |  |
| `openidconnect/handler/token.py` | 360 | `Token request denied: Client has no tenants.` |  |
| `openidconnect/handler/token.py` | 369 | `Token request denied: Unauthorized tenant access.` |  |
| `openidconnect/handler/token.py` | 379 | `Token request granted.` |  |
| `openidconnect/handler/token.py` | 561 | `Token request denied: Track ID transfer failed because of invalid Authorization header` |  |
| `openidconnect/handler/token.py` | 585 | `Token request denied: Failed to produce session track ID` |  |
| `openidconnect/service.py` | 762 | `Token request granted.` | Duplicate: service-layer path for client credentials may produce a second audit entry. |

#### Cookie Bouncer

| File | Line | Message | Notes |
|---|---|---|---|
| `cookie/handler.py` | 374 | `Token request denied: No 'client_id' in request query` | `token_type: "cookie"` |
| `cookie/handler.py` | 384 | `Token request denied: Client not found` | `token_type: "cookie"` |
| `cookie/handler.py` | 394 | `Token request denied: Unsupported grant type` | `token_type: "cookie"` |
| `cookie/handler.py` | 409 | `Token request denied: No 'code' in request query` | `token_type: "cookie"` |
| `cookie/handler.py` | 422 | `Token request denied: Invalid or expired authorization code` | `token_type: "cookie"` |
| `cookie/handler.py` | 462 | `Token request denied: Track ID transfer failed because of invalid Authorization header` | `token_type: "cookie"` |
| `cookie/handler.py` | 516 | `Token request denied: Webhook error` | `token_type: "cookie"` |
| `cookie/handler.py` | 525 | `Token request granted` | `token_type: "cookie"` |

#### Credentials Lifecycle

| File | Line | Message | Key `struct_data` |
|---|---|---|---|
| `credentials/service.py` | 427 | `Credentials created` | `cid`, `by_cid` |
| `credentials/service.py` | 542 | `Credentials updated` | `cid`, `by_cid`, `attributes`. If `suspended` is among the changed attributes, also emit `Credentials suspended` or `Credentials activated` with the new `suspended` value. |
| `credentials/service.py` | 594 | `Credentials deleted` | `cid`, `by_cid` |
| `credentials/registration/service.py` | 112 | `Credentials created` | `cid`, `by_cid` |
| `credentials/registration/service.py` | 273 | `Invitation accepted by a new user` | `cid` |
| `credentials/registration/service.py` | 334 | `Invitation accepted by an existing user` | `cid`, `t`, `r` |

#### Password Management

| File | Line | Message | Notes |
|---|---|---|
| `credentials/change_password/handler.py` | 72 | `Password change failed: Authentication failed` |  |
| `credentials/change_password/handler.py` | 84 | `Password change denied: Reusing old passwords is not allowed.` |  |
| `credentials/change_password/handler.py` | 97 | `Password change denied: New password too weak.` |  |
| `credentials/change_password/handler.py` | 107 | `Password change failed: {ExceptionClass}` |  |
| `credentials/change_password/handler.py` | 114 | `Password change successful` |  |
| `credentials/change_password/handler.py` | 144 | `Password reset failed: Invalid password reset token` | **Security concern:** logs raw `token` value. |
| `credentials/change_password/handler.py` | 154 | `Password reset denied: Credentials suspended` |  |
| `credentials/change_password/handler.py` | 160 | `Password reset denied: New password too weak.` |  |
| `credentials/change_password/handler.py` | 170 | `Password reset failed: {ExceptionClass}` |  |
| `credentials/change_password/handler.py` | 185 | `Password reset successful` |  |

#### Client Management

| File | Line | Message | Key `struct_data` | Notes |
|---|---|---|---|---|
| `client/service.py` | 298 | `Client secret updated.` | `client_id` | Does not record the acting agent. |

---

## 4. Consistency Analysis

### 4.1 Message Style Inconsistencies

| Aspect | Inconsistency | Examples |
|---|---|---|
| **Trailing punctuation** | Some messages end with a period, others do not. | `Token request granted.` vs `Cookie request granted` (will be standardized as `Token request granted` with `token_type: "cookie"`) |
| **Success verb** | Multiple verbs used for success. | `successful`, `granted`, `created`, `updated`, `deleted`, `accepted` |
| **Failure phrasing** | `failed:` vs `denied:` is used inconsistently. | `Authentication failed` vs `Token request denied: ...` |
| **Casing** | `Credentials created` vs `Client secret updated.` (lowercase resource after sentence case). |  |
| **Noun/verb agreement** | Some messages use `{Action} successful`, others use past-tense passive. | `Authorization successful` vs `Credentials updated` |

**Recommendation:** Adopt a single convention, e.g.,

- Success: `{Action} succeeded` or `{Resource} {verb}ed` (e.g., `Credentials created`, `Session deleted`).
- Failure: `{Action} failed: {reason}` for technical errors, `{Action} denied: {reason}` for policy/authorization denials.
- Be consistent with trailing punctuation; prefer no trailing period for structured audit messages.

### 4.2 `struct_data` Key Inconsistencies

| Concept | Primary Key | Alternative Key | Locations |
|---|---|---|---|
| **Request IP address** | `from_ip` | `fi` | `fi` used in `authn/m2m.py` and `cookie/service.py`. Will be extracted from `asab.contextvars.Request` by the enrichment helper. |
| **Session ID** | `sid` | `psid`, `lsid`, `parent_sid` | `parent_sid` in `session/service.py` (on `L`) |
| **Acting agent** | `by_cid` (to be renamed) | `impersonator_cid` | `by_cid` for admin CRUD; `impersonator_cid` for impersonation; absent for client secret update. Should be derived from `Authz.CredentialsId` via the enrichment helper. |
| **Tenants** | `t` (list) | `scope` (string) | `t` in authorization/registration; `scope` in OAuth token denials |
| **Error detail** | `reason` | `e` | `e` used in `openidconnect/handler/authorize.py` |
| **Role** | `role` (in `authz/role/service.py` on `L`) | `r` (in invitation acceptance) |  |

**Specific observations:**

1. **IP address key (`from_ip` vs `fi`)**: The same semantic value is logged under two different keys. M2M and anonymous cookie flows use `fi`; all other flows use `from_ip`. Standardize on `from_ip` by extracting the IP from `asab.contextvars.Request` in the enrichment helper. This also eliminates the need to pass `request` or `from_ip` through many service methods.
2. **Session ID object access**: Audit logs access `session.SessionId`, `session.Id`, `session.Session.Id`, or `str(session.Session.Id)` inconsistently. The logged `sid` should always be a stable string identifier.
3. **Acting agent attribution**: The credential CRUD operations record `by_cid` (the admin acting). Impersonation records `impersonator_cid`. Client secret rotation records neither. Tenant/role/resource mutations do not record the acting agent in audit logs (they only log on `L`). With the context enrichment helper, `agent_cid` can be populated automatically for every authenticated request, eliminating the need to pass `by_cid` through method signatures. Internal/system calls that have no `Authz` context will simply omit the field.
4. **Tenant context**: Most credential and password audit events do not include tenant context, despite SeaCat Auth being multi-tenant.
5. **Login session ID**: Real `lsid` is used in interactive login; external login uses a literal `"<external-login>"`; M2M has no `lsid`.
6. **Error code**: OAuth authorization errors use the key `e` for the error code. A clearer key such as `error` or `error_code` would be more explicit.

### 4.3 Log Level Inconsistencies

- 57 of 60 calls use `asab.LOG_NOTICE` regardless of whether the event is a success or failure.
- Only impersonation failures use `warning` (2) and `exception` (1).
- Authentication failures, token denials, password failures, and cookie denials are all logged at the same level as their success counterparts.

**Recommendation:** Consider a severity convention for audit events:

- `LOG_NOTICE` for normal successful security events.
- `LOG_WARNING` or dedicated audit-level for policy denials (failed logins, unauthorized access, invalid tokens).
- `LOG_ERR` for unexpected security failures (exceptions, impersonation errors).

Because `AuditLogger` is a plain Python logger, the application can later configure filters/sinks based on level; establishing consistent levels makes this possible.

### 4.4 Duplicate and Near-Duplicate Audit Events

| Event | AuditLogger Location | Duplicate/Related Location | Problem |
|---|---|---|---|
| Client credentials token granted | `openidconnect/handler/token.py:379` | `openidconnect/service.py:762` | A single successful client-credentials flow may produce two audit entries. |
| Credentials created | `credentials/service.py:427` | `credentials/providers/mongodb.py:124`, `credentials/providers/m2m_mongodb.py:85` | Provider-level logs on `L` duplicate the service-level audit. |
| Credentials updated | `credentials/service.py:542` | `credentials/providers/mongodb.py:165` | Same as above. |

**Recommendation:** Make the service layer the authoritative audit point and remove or downgrade provider-level logs.

### 4.5 Context-Aware Audit Enrichment

ASAB provides three context variables that can be used to enrich every audit entry automatically:

- `asab.contextvars.Request` — a `contextvars.ContextVar` containing the current `aiohttp.web.Request`. From it we can extract the client IP address (`from_ip`) including `X-Forwarded-For` headers.
- `asab.contextvars.Tenant` — a `contextvars.ContextVar` containing the current tenant ID string.
- `asab.contextvars.Authz` — a `contextvars.ContextVar` containing an `asab.web.auth.Authorization` object with:
  - `CredentialsId` — the acting agent's credentials ID (corresponds to `by_cid` in current audit logs).
  - `SessionId` — the acting agent's SSO session ID.
  - `has_superuser_access()` — whether the agent has superuser privileges.

All three context variables raise `LookupError` when not set, which happens for internal system-initiated calls that do not go through the ASAB web authorization layer. A helper that guards against `LookupError` can therefore safely be used in any code path.

> **Note on placement**: If the helper is placed in `seacatauth/__init__.py`, importing `generic` from `seacatauth` may create a circular import. Place the helper in a dedicated module (e.g., `seacatauth/audit.py`) or inline the small IP extraction logic to avoid this.

**Proposed helper**

```python
import asab.contextvars


def audit_struct_data(extra: dict | None = None) -> dict:
    """
    Build a base struct_data dict for audit logs, enriched from the ASAB
    Request, Authz, and Tenant context variables.

    Safe to call from system-initiated code that has not set these context variables.
    Caller-provided values take precedence over inferred values.
    """
    struct_data = {}
    if extra:
        struct_data.update(extra)

    try:
        request = asab.contextvars.Request.get()
    except LookupError:
        request = None

    if request is not None:
        struct_data.setdefault("from_ip", generic.get_request_access_ips(request))

    try:
        authz = asab.contextvars.Authz.get()
    except LookupError:
        authz = None

    if authz is not None:
        if authz.CredentialsId is not None:
            struct_data.setdefault("agent_cid", authz.CredentialsId)
        if authz.SessionId is not None:
            struct_data.setdefault("agent_sid", authz.SessionId)
        if authz.has_superuser_access():
            struct_data.setdefault("superuser", True)

    try:
        tenant = asab.contextvars.Tenant.get()
    except LookupError:
        tenant = None

    if tenant is not None:
        struct_data.setdefault("tenant", tenant)

    return struct_data
```

**Usage example**

```python
AuditLogger.log(asab.LOG_NOTICE, "Credentials created", struct_data=audit_struct_data({
    "cid": credentials_id,
}))
```

**Impact on existing method signatures**

Several service methods currently take an explicit `request`, `from_ip`, `agent_cid`, or `by_cid` argument (e.g., `openidconnect/handler/token.py`, `credentials/service.py`). With the helper, those arguments become redundant and can be deprecated or removed. The user noted that making some method arguments unused is acceptable.

**Enrichment policy**

| Field | Source | When omitted |
|---|---|---|
| `from_ip` | `Request.get()` + `generic.get_request_access_ips()` | No `Request` context (system/internal calls) |
| `agent_cid` | `Authz.CredentialsId` | No `Authz` context (system/internal calls) |
| `agent_sid` | `Authz.SessionId` | No `Authz` context or no session |
| `superuser` | `Authz.has_superuser_access()` | Not a superuser (omit rather than `False`) |
| `tenant` | `Tenant.get()` | No tenant context or global operation |

Using `setdefault` ensures that explicit caller-provided values are not overwritten. This is important for cases where the subject's tenant differs from the API caller's tenant (e.g., a global admin acting on a specific tenant), or where a method already has a more specific `from_ip` value.

#### AuditLogger convenience methods

To ensure enrichment is always applied consistently, extend or wrap `AuditLogger` so that convenience methods such as `notice()`, `warning()`, `error()`, and `exception()` automatically merge `audit_struct_data()` with the caller-provided `struct_data`.

**Option A: Subclass `logging.Logger`**

```python
class AuditLogger(logging.Logger):
    def notice(self, message, struct_data=None):
        return self.log(asab.LOG_NOTICE, message, struct_data=audit_struct_data(struct_data))

    def warning(self, message, struct_data=None):
        return super().warning(message, struct_data=audit_struct_data(struct_data))

    def error(self, message, struct_data=None):
        return super().error(message, struct_data=audit_struct_data(struct_data))

    def exception(self, message, struct_data=None, exc_info=True):
        return super().exception(message, struct_data=audit_struct_data(struct_data), exc_info=exc_info)


logging.setLoggerClass(AuditLogger)
AuditLogger = logging.getLogger("AUDIT")
```

**Option B: Module-level wrapper functions**

```python
def audit_log(level, message, struct_data=None):
    AuditLogger.log(level, message, struct_data=audit_struct_data(struct_data))


def audit_notice(message, struct_data=None):
    audit_log(asab.LOG_NOTICE, message, struct_data=struct_data)


def audit_warning(message, struct_data=None):
    audit_log(asab.LOG_WARNING, message, struct_data=struct_data)


def audit_error(message, struct_data=None):
    audit_log(asab.LOG_ERR, message, struct_data=struct_data)
```

With either approach, call sites become simpler and consistent:

```python
AuditLogger.notice("Credentials created", struct_data={"cid": credentials_id})
# or
audit_notice("Credentials created", struct_data={"cid": credentials_id})
```

This also removes the current inconsistency where most calls use `AuditLogger.log(asab.LOG_NOTICE, ...)` while impersonation failures use `AuditLogger.warning()` and `AuditLogger.exception()` directly without a shared enrichment path.

### 4.6 Attribute Renaming Considerations

**Renaming `by_cid` to `agent_cid`**

`by_cid` is used in credential CRUD and invitation events to record the acting agent. Renaming it to `agent_cid` is recommended for the following reasons:

- **Clarity**: `agent_cid` explicitly identifies the actor performing the operation, whereas `by_cid` is ambiguous (created by? modified by? audited by?).
- **Alignment**: `agent_cid` mirrors the ASAB `Authz.CredentialsId` concept and is a common term in IAM/audit systems.
- **Consistency**: It avoids the need to explain what `by_cid` means in the audit schema documentation.

Counter-arguments:

- **Backward compatibility**: Existing audit consumers, SIEM parsers, and stored logs use `by_cid`. A hard rename is a breaking change.

**Recommendation**: Rename `by_cid` to `agent_cid` in the new helper and in all new/modified audit events. For a transition period, emit both `agent_cid` and `by_cid` with the same value, then remove `by_cid` in a later release. Alternatively, introduce an explicit audit schema version.

**Other attributes worth renaming**

| Current Key | Proposed Key | Rationale | Priority |
|---|---|---|---|
| `fi` | `from_ip` | Extracted from `Request` context by the helper; `fi` is eliminated rather than renamed. | High |
| `e` | `error` or `error_code` | `e` is opaque; a self-describing key is clearer. | High |
| `t` | `tenants` | Less abbreviation, self-describing. | Medium |
| `r` | `roles` | Less abbreviation, self-describing. | Medium |
| `lsid` | `login_session_id` or `login_sid` | Reduce abbreviation; `login_sid` is compact and clear. | Low |
| `psid` | `parent_session_id` or `parent_sid` | Reduce abbreviation; `parent_sid` is compact and clear. | Low |

**Recommendation**: Apply the `fi` and `e` renames immediately. Consider `t`/`r` and `lsid`/`psid` renames as part of a broader schema consistency pass, documenting any changes clearly for operators.

---

## 5. Missing Audit Events (Gaps)

### 5.1 Authentication Failures (logged only on `L`)

| File | Lines | Event | Why It Matters |
|---|---|---|---|
| `authn/m2m.py` | 37–73 | M2M basic-auth failures: missing token, malformed token, wrong credentials, non-M2M credential type, basic auth failure. | Symmetric with success at line 98; failure is currently only logged to `L`. |
| `authn/service.py` | 307–315 | `authenticate()`: fake login session, suspended user, wrong descriptor. | Parent handler audits overall failure but not these specific reasons. |
| `authn/service.py` | 424–436 | `create_impersonated_session()`: target not found, target is superuser. | Handler-level impersonation audit exists, but service-layer guardrails are not audited. |
| `authn/service.py` | 525–546 | `prepare_seacat_login()`: credentials not found, machine credentials denied, suspended, no login descriptor. | Pre-auth failure reasons are lost to audit. |
| `authn/login_descriptor.py` | 102–106 | `LoginDescriptor.authenticate()`: per-factor failure. | Useful for brute-force/MFA analysis. |
| `credentials/providers/mongodb.py` | 337–359 | Provider `authenticate()` failures. | Password verification failure is a classic audit event. |
| `credentials/providers/xmongodb.py` | 154–175 | Same provider failures. | Same as above. |
| `credentials/providers/ldap.py` | 322 | Invalid LDAP credentials. | External directory failure. |
| `authn/webauthn/service.py` | 503, 520 | WebAuthn login failures. | Passkey authentication failure. |
| `authn/login_factors/webauthn.py` | 29 | Missing WebAuthn data. | Incomplete passkey attempt. |
| `external_login/authentication/service.py` | 266–600 | External login, signup, and pairing failures. | Only successful external login is audited. |
| `external_login/authentication/providers/saml.py` | 199 | SAML authentication failed. | External IdP failure. |
| `external_login/authentication/providers/oauth2.py` | 322, 325 | Invalid/expired ID token. | Token validation failure. |

### 5.2 Authorization and Access Denials

| File | Lines | Event |
|---|---|---|
| `api/auth.py` | 84, 89–90 | API session not found; anonymous session denied API access. |
| `generic.py` | 157–161 | Nginx introspection: credentials not authorized for tenant or resource. |
| `openidconnect/handler/introspect.py` | 98–154 | Access token missing, session not found, API key mismatch, client mismatch, max age exceeded. |
| `openidconnect/service.py` | 394, 397, 443 | Tenant access denied. |
| `cookie/handler.py` | 162–163, 544–579 | Anonymous user denied, cookie/session not found, client mismatch, max age exceeded. |
| `openidconnect/handler/authorize.py` | 376–377, 477 | Anonymous session not allowed, login required. |
| `batman/handler.py` | 56–70 | Batman introspection failures and unauthorized access. |
| `client/service.py` | 416–442 | Unexpected client auth method, expired secret, missing secret, incorrect secret. |
| `tenant/service.py` | 218–221 | Unauthorized tenant assignment/unassignment. |

### 5.3 Session Lifecycle

| File | Lines | Event |
|---|---|---|
| `session/service.py` | 249 | Session created (currently on `L`). |
| `session/service.py` | 290 | Session expiration updated. |
| `session/service.py` | 550 | Session deleted. |
| `session/service.py` | 585–588 | Bulk session deletion. |
| `session/service.py` | 609 | Root session changed between authorize and token request (suspicious). |
| `session/handler.py` | 107–109 | Delete all sessions (admin action). |
| `session/handler.py` | 150–153 | Delete all sessions by credentials ID (admin forced logout). |
| `session/handler.py` | 164–166 | Delete own sessions (user global logout). |
| `session/token.py` | 93 | Session token created. |
| `session/token.py` | 135 | Session token validity extended. |
| `session/token.py` | 149, 174 | Session token deleted / bulk deleted. |
| `openidconnect/handler/authorize.py` | 398–423 | Forced re-authentication / session invalidation by client request. |

### 5.4 IAM Mutations (Roles, Tenants, Resources)

| File | Lines | Event |
|---|---|---|
| `authz/role/service.py` | 105, 128 | Preset role created/updated. |
| `authz/role/service.py` | 396 | Role created. |
| `authz/role/service.py` | 444 | Role deleted. |
| `authz/role/service.py` | 514 | Role updated. |
| `authz/role/service.py` | 774–777 | Role assigned to credentials. |
| `authz/role/service.py` | 796–799 | Role unassigned from credentials. |
| `authz/role/service.py` | 826–828 | Bulk role assignments deleted. |
| `authz/resource/service.py` | 209, 250, 263, 270, 281, 298, 327 | Resource/permission create, update, delete, soft-delete, undelete, rename. |
| `tenant/providers/mongodb.py` | 100, 127, 136, 198, 235 | Tenant create/update/delete/unassign. |
| `tenant/service.py` | 245–248, 286–288 | Tenant assignment to credentials. |
| `tenant/handler.py` | 409–483 | Failed bulk tenant/role assignment/unassignment. |

### 5.5 Credential and MFA Mutations

| File | Lines | Event |
|---|---|---|
| `credentials/service.py` | 384–421 | Failed credential creation attempts. |
| `credentials/service.py` | 461–526 | Failed credential update attempts. |
| `credentials/service.py` | 561–565 | Denied credential deletion (read-only provider). |
| `credentials/registration/service.py` | 261 | Credentials registration completed. |
| `external_login/credentials/service.py` | 151 | External login account added. |
| `external_login/credentials/service.py` | 303 | External login accounts deleted with credentials. |
| `authn/otp/service.py` | 46, 69, 111, 118, 125, 133, 158 | TOTP activation/deactivation/secret creation. |
| `authn/webauthn/service.py` | 144, 253, 278, 292 | WebAuthn credential created, updated, deleted. |
| `credentials/change_password/handler.py` | 327–370 | Lost password reset denial/failure paths. |

### 5.6 Client and API Key Lifecycle

| File | Lines | Event | Notes |
|---|---|---|---|
| `client/service.py` | 243 | Client created. |  |
| `client/service.py` | 315 | Client updated. | Important because client config changes affect authorization. |
| `client/service.py` | 329 | Client deleted. |  |
| `apikey/service.py` | 84–149 | API key creation. | **Currently has no audit logging at all.** High priority. |
| `apikey/service.py` | 159–163 | Cross-tenant API key deletion attempt. |  |
| `apikey/service.py` | 167 | API key deletion. |  |

### 5.7 Other Notable Gaps

- **API key lifecycle** (`apikey/service.py`) has zero audit events. API keys are long-lived credentials and their creation, use, and revocation are highly sensitive.
- **External login pairing** is only partially audited at the final success step; all intermediate failures and account-linking operations are missing.
- **Session introspection** (cookie, OIDC, Batman) logs denials on `L` but not on `AuditLogger`, making it hard to detect probing or abuse.
- **Failed admin actions** (credential creation/update denied, bulk tenant/role assignment failures) are not recorded in the audit log, so attempted abuse of admin APIs is not visible.
- **Provisioning plaintext secret**: `provisioning/service.py` logs the superuser password on `L` (operational logger). This should never be logged at all, neither on `L` nor `AuditLogger`.

---

## 6. System Logs That Should Be Audit Logs (Selected)

The following `L.*` calls are security-relevant and should be migrated to `AuditLogger` (or mirrored there). The list is grouped by priority.

### Tier 1 — Security/Authentication Events (Highest Priority)

| File | Lines | Message / Event | Suggested Audit Message |
|---|---|---|---|
| `authn/m2m.py` | 37–73 | M2M authentication failures | `Authentication failed` with `m2m: True`, `cid`, `from_ip` |
| `authn/service.py` | 307–315 | Login failure reasons (fake session, suspended) | `Authentication failed` with `reason` |
| `authn/service.py` | 424–436 | Impersonation service-layer denials | `Impersonation failed` |
| `authn/service.py` | 525–546 | `prepare_seacat_login` failures | `Authentication failed` with `reason` |
| `credentials/providers/mongodb.py` | 337–359 | Provider password failures | `Authentication failed` with `reason` |
| `credentials/providers/xmongodb.py` | 154–175 | Provider password failures | Same as above |
| `credentials/providers/ldap.py` | 322 | LDAP authentication failure | `Authentication failed` with `dn` |
| `authn/webauthn/service.py` | 503, 520 | WebAuthn login failure | `Authentication failed` with `reason` |
| `external_login/authentication/service.py` | 266–600 | External login/pairing failures | `Authentication failed` / `External account pairing failed` |
| `generic.py` | 157–161 | Resource access denied | `Access denied` with `cid`, `tenant`, `resources` |
| `openidconnect/handler/introspect.py` | 98–154 | Token/API key introspection failures | `Introspection denied` |
| `cookie/handler.py` | 544–579 | Cookie introspection failures | `Cookie introspection denied` |
| `client/service.py` | 416–442 | Client authentication failures | `Client authentication failed` |

### Tier 2 — IAM/Admin Mutations

| File | Lines | Event | Suggested Audit Message |
|---|---|---|---|
| `authz/role/service.py` | 396, 444, 514 | Role created/deleted/updated | `Role created` / `Role deleted` / `Role updated` |
| `authz/role/service.py` | 774–777, 796–799 | Role assign/unassign | `Role assigned` / `Role unassigned` with `cid`, `role`, `agent_cid` |
| `authz/resource/service.py` | 209, 250, 263, 270, 281, 298, 327 | Resource changes | `Resource created/updated/deleted/undeleted/renamed` |
| `tenant/providers/mongodb.py` | 100, 127, 136 | Tenant CRUD | `Tenant created/updated/deleted` |
| `tenant/service.py` | 245–248, 286–288 | Tenant assignment | `Tenant assigned` / `Tenants assigned` with `cid`, `agent_cid` |
| `credentials/service.py` | 384–421, 461–526, 561–565 | Failed credential mutations | `Credentials creation denied` / `Credentials update denied` / `Credentials deletion denied` |
| `client/service.py` | 243, 315, 329 | Client CRUD | `Client created` / `Client updated` / `Client deleted` |

### Tier 3 — Session and Token Lifecycle

| File | Lines | Event | Suggested Audit Message |
|---|---|---|---|
| `session/service.py` | 249 | Session created | `Session created` with `sid`, `type`, `parent_sid`, `cid` |
| `session/service.py` | 550, 585–588 | Session deletion | `Session deleted` / `Sessions deleted` |
| `session/handler.py` | 107–109, 150–153, 164–166 | Bulk session deletion | `Sessions deleted` with `requested_by` |
| `session/token.py` | 93, 135, 149, 174 | Token create/extend/delete | `Session token created/extended/deleted` |
| `authn/otp/service.py` | 133, 158 | TOTP activated/secret created | `TOTP activated` / `TOTP secret created` |
| `authn/webauthn/service.py` | 144, 253, 278, 292 | WebAuthn credential CRUD | `WebAuthn credential created/updated/deleted` |
| `apikey/service.py` | 84–149, 167 | API key create/delete | `API key created` / `API key deleted` |

---

## 7. Security and Privacy Concerns

1. **Raw password reset token logged** (`credentials/change_password/handler.py:144`). The invalid token value is included in `struct_data` on failure. Tokens should never be logged in plain text. Remove the `token` field from the audit entry; if correlation is needed, log a hash or prefix only.
2. **No tenant context in credential/password audit events**. Most credential operations happen within a tenant scope, but the audit log does not record it, limiting multi-tenant forensic analysis.
3. **No acting agent in client secret update** (`client/service.py:298`). Client secret rotation is a sensitive operation; the acting `agent_cid` should be included via the context enrichment helper.
4. **Provisioning logs plaintext password** (`provisioning/service.py:97`). This is an operational logging issue, not audit logging, but it must be fixed; secrets should never be logged.
5. **Duplicate audit entries for client credentials** (`token.py:379` and `service.py:762`). Remove the duplicate to avoid confusion and log volume bloat.

---

## 8. Recommendations and Prioritization

### 8.1 Immediate (High Priority)

1. **Fix the password reset token leak** in `credentials/change_password/handler.py:144`.
2. **Implement the `audit_struct_data()` helper** in a central module (e.g., `seacatauth/__init__.py` or a new `seacatauth/audit.py`) and use it for all new audit events. This provides automatic `from_ip`, `agent_cid`, `agent_sid`, `tenant`, and `superuser` enrichment and removes the need to thread `request`, `from_ip`, and `by_cid` through every service method.
3. **Add audit logging for API key lifecycle** (`apikey/service.py`).
4. **Mirror authentication failures to `AuditLogger`** in:
   - `authn/m2m.py`
   - `credentials/providers/mongodb.py`, `xmongodb.py`, `ldap.py`
   - `authn/login_descriptor.py` (per-factor failures)
   - `authn/webauthn/service.py` and `authn/login_factors/webauthn.py`
5. **Add audit logging for session lifecycle events** (`session/service.py`, `session/handler.py`, `session/token.py`).

### 8.2 Short Term (Medium Priority)

1. **Migrate IAM mutations to `AuditLogger`**:
   - Role CRUD and assignment (`authz/role/service.py`)
   - Resource/permission CRUD (`authz/resource/service.py`)
   - Tenant CRUD and assignment (`tenant/providers/mongodb.py`, `tenant/service.py`)
2. **Add audit logging for failed credential mutations** (`credentials/service.py` denial paths).
3. **Add audit logging for MFA/WebAuthn lifecycle** (`authn/otp/service.py`, `authn/webauthn/service.py`).
4. **Add audit logging for external login pairing** (`external_login/credentials/service.py`, `external_login/authentication/service.py` failures).
5. **Standardize `struct_data` keys**: use `from_ip` everywhere (rename `fi`), rename `by_cid` to `agent_cid` via the context enrichment helper, rename `e` to `error` or `error_code`, and ensure `tenant` is included where applicable. Emit backward-compatible keys during a transition period if needed.
6. **Standardize cookie bouncer audit messages**: change `Cookie request denied` / `Cookie request granted` to `Token request denied` / `Token request granted` and add `token_type: "cookie"` to the `struct_data`.
7. **Make credentials suspension explicit**: when `suspended` is modified in `credentials/service.py:update_credentials`, emit both `Credentials updated` and the explicit `Credentials suspended` / `Credentials activated` event with the new `suspended` value.

### 8.3 Long Term (Polish and Maintenance)

1. **Standardize message style**: adopt a single grammar, punctuation, and casing convention across all audit messages.
2. **Standardize log levels**: successes at `LOG_NOTICE`, policy denials at `LOG_WARNING`, and unexpected errors at `LOG_ERR`.
3. **Deduplicate provider-level logs**: make `credentials/service.py` the authoritative audit point; remove or downgrade `L.log` calls in `credentials/providers/mongodb.py`, `m2m_mongodb.py`, etc.
4. **Wrap `AuditLogger`** with convenience methods (`notice()`, `warning()`, `error()`, `exception()`) that automatically merge `audit_struct_data()` and enforce required fields (e.g., `cid`, `tenant`, `from_ip`) and message conventions. This removes the inconsistency between `AuditLogger.log(asab.LOG_NOTICE, ...)` and `AuditLogger.warning(...)` call sites and ensures enrichment is always applied.
5. **Document the audit event schema** for operators and SIEM integrators.

---

## 9. Appendix: Complete AuditLogger Call Site Table

> This table reflects the **current call sites** and the **planned target state** for message text and `struct_data`. Keys such as `by_cid` and `fi` are planned to be renamed to `agent_cid` and `from_ip` respectively, cookie bouncer messages will be standardized to `Token request ...`, and `agent_sid`, `tenant`, and `superuser` enrichment will be added via the context-aware helper.

| # | File | Line | Level | Message | Key `struct_data` |
|---|---|---|---|---|---|
| 1 | `authn/handler/public.py` | 189 | `LOG_NOTICE` | `Authentication failed` | `cid`, `lsid`, `ident`, `from_ip` |
| 2 | `authn/handler/public.py` | 299 | `LOG_NOTICE` | `Logout successful` | `cid`, `sid`, `token_type` |
| 3 | `authn/service.py` | 360 | `LOG_NOTICE` | `Authentication successful` | `cid`, `lsid`, `sid`, `from_ip` |
| 4 | `authn/m2m.py` | 98 | `LOG_NOTICE` | `Authentication successful` | `cid`, `sid`, `fi`, `m2m` |
| 5 | `authn/m2m.py` | 106 | `LOG_NOTICE` | `Authentication failed` | `cid`, `fi`, `m2m` |
| 6 | `authn/handler/account.py` | 170 | `warning` | `Impersonation failed: Target credentials ID not found` | `impersonator_cid`, `impersonator_sid`, `target_cid`, `from_ip` |
| 7 | `authn/handler/account.py` | 178 | `warning` | `Impersonation failed: Access denied` | same |
| 8 | `authn/handler/account.py` | 186 | `exception` | `Impersonation failed: Unexpected error ({e})` | same |
| 9 | `authn/handler/account.py` | 194 | `LOG_NOTICE` | `Impersonation successful` | `impersonator_cid`, `impersonator_sid`, `target_cid`, `target_sid`, `from_ip` |
| 10 | `external_login/authentication/service.py` | 672 | `LOG_NOTICE` | `Authentication successful` | `cid`, `lsid`, `sid`, `from_ip`, `authn_by` |
| 11 | `cookie/service.py` | 209 | `LOG_NOTICE` | `Authentication successful` | `anonymous`, `cid`, `client_id`, `track_id`, `fi` |
| 12 | `openidconnect/handler/session.py` | 71 | `LOG_NOTICE` | `Logout successful` | `cid`, `sid`, `psid`, `token_type` |
| 13 | `openidconnect/handler/authorize.py` | 619 | `LOG_NOTICE` | `Authorization successful` | `psid`, `sid`, `cid`, `t`, `client_id`, `anonymous`, `from_ip`, `scope` |
| 14 | `openidconnect/handler/authorize.py` | 939 | `LOG_NOTICE` | `Authorization failed` | `e`, `cid`, `client_id`, `**error.StructData` |
| 15 | `openidconnect/handler/token.py` | 101 | `LOG_NOTICE` | `Token request denied: Unauthorized client.` | `from_ip`, `client_id`, `redirect_uri` |
| 16 | `openidconnect/handler/token.py` | 117 | `LOG_NOTICE` | `Token request denied: Unsupported grant type.` | `from_ip`, `grant_type`, `client_id`, `redirect_uri` |
| 17 | `openidconnect/handler/token.py` | 128 | `LOG_NOTICE` | `Token request denied: Unauthorized client.` | `from_ip`, `grant_type`, `client_id`, `redirect_uri` |
| 18 | `openidconnect/handler/token.py` | 136 | `LOG_NOTICE` | `Token request denied: Invalid client.` | `from_ip`, `grant_type`, `client_id`, `redirect_uri` |
| 19 | `openidconnect/handler/token.py` | 144 | `LOG_NOTICE` | `Token request denied: Invalid scope.` | `from_ip`, `grant_type`, `client_id`, `scope`, `redirect_uri` |
| 20 | `openidconnect/handler/token.py` | 169 | `LOG_NOTICE` | `Token request denied: Invalid or expired authorization code.` | `from_ip`, `grant_type`, `client_id`, `redirect_uri` |
| 21 | `openidconnect/handler/token.py` | 182 | `LOG_NOTICE` | `Token request denied: Code challenge failed.` | `from_ip`, `grant_type`, `client_id`, `redirect_uri` |
| 22 | `openidconnect/handler/token.py` | 195 | `LOG_NOTICE` | `Token request denied: Redirect URI mismatch.` | `from_ip`, `grant_type`, `client_id`, `redirect_uri` |
| 23 | `openidconnect/handler/token.py` | 204 | `LOG_NOTICE` | `Token request denied: Invalid request.` | `from_ip`, `grant_type`, `client_id`, `redirect_uri` |
| 24 | `openidconnect/handler/token.py` | 220 | `LOG_NOTICE` | `Token request granted.` | `cid`, `sid`, `client_id`, `grant_type`, `from_ip` |
| 25 | `openidconnect/handler/token.py` | 266 | `LOG_NOTICE` | `Token request denied: Invalid or expired refresh token.` | `from_ip`, `grant_type`, `client_id` |
| 26 | `openidconnect/handler/token.py` | 278 | `LOG_NOTICE` | `Token request denied: Cannot verify client.` | `from_ip`, `grant_type`, `client_id` |
| 27 | `openidconnect/handler/token.py` | 296 | `LOG_NOTICE` | `Token request granted.` | `cid`, `sid`, `client_id`, `grant_type`, `from_ip` |
| 28 | `openidconnect/handler/token.py` | 328 | `LOG_NOTICE` | `Token request denied: Missing scope parameter.` | `from_ip`, `grant_type`, `client_id` |
| 29 | `openidconnect/handler/token.py` | 348 | `LOG_NOTICE` | `Token request denied: Client does not have Seacat Auth credentials enabled.` | `from_ip`, `grant_type`, `client_id` |
| 30 | `openidconnect/handler/token.py` | 360 | `LOG_NOTICE` | `Token request denied: Client has no tenants.` | `from_ip`, `grant_type`, `client_id`, `scope` |
| 31 | `openidconnect/handler/token.py` | 369 | `LOG_NOTICE` | `Token request denied: Unauthorized tenant access.` | `from_ip`, `grant_type`, `client_id`, `scope` |
| 32 | `openidconnect/handler/token.py` | 379 | `LOG_NOTICE` | `Token request granted.` | `cid`, `sid`, `client_id`, `grant_type`, `from_ip` |
| 33 | `openidconnect/handler/token.py` | 561 | `LOG_NOTICE` | `Token request denied: Track ID transfer failed because of invalid Authorization header` | `from_ip`, `cid`, `client_id` |
| 34 | `openidconnect/handler/token.py` | 585 | `LOG_NOTICE` | `Token request denied: Failed to produce session track ID` | `from_ip`, `cid`, `client_id` |
| 35 | `openidconnect/service.py` | 762 | `LOG_NOTICE` | `Token request granted.` | `cid`, `sid`, `client_id`, `grant_type`, `from_ip` |
| 36 | `cookie/handler.py` | 374 | `LOG_NOTICE` | `Token request denied: No 'client_id' in request query` | `from_ip`, `token_type: "cookie"` |
| 37 | `cookie/handler.py` | 384 | `LOG_NOTICE` | `Token request denied: Client not found` | `from_ip`, `client_id`, `token_type: "cookie"` |
| 38 | `cookie/handler.py` | 394 | `LOG_NOTICE` | `Token request denied: Unsupported grant type` | `client_id`, `from_ip`, `grant_type`, `token_type: "cookie"` |
| 39 | `cookie/handler.py` | 409 | `LOG_NOTICE` | `Token request denied: No 'code' in request query` | `client_id`, `from_ip`, `token_type: "cookie"` |
| 40 | `cookie/handler.py` | 422 | `LOG_NOTICE` | `Token request denied: Invalid or expired authorization code` | `client_id`, `from_ip`, `token_type: "cookie"` |
| 41 | `cookie/handler.py` | 462 | `LOG_NOTICE` | `Token request denied: Track ID transfer failed because of invalid Authorization header` | `cid`, `sid`, `client_id`, `from_ip`, `redirect_uri`, `token_type: "cookie"` |
| 42 | `cookie/handler.py` | 516 | `LOG_NOTICE` | `Token request denied: Webhook error` | `cid`, `sid`, `client_id`, `from_ip`, `redirect_uri`, `token_type: "cookie"` |
| 43 | `cookie/handler.py` | 525 | `LOG_NOTICE` | `Token request granted` | `cid`, `sid`, `client_id`, `from_ip`, `redirect_uri`, `token_type: "cookie"` |
| 44 | `credentials/service.py` | 427 | `LOG_NOTICE` | `Credentials created` | `cid`, `by_cid` |
| 45 | `credentials/service.py` | 542 | `LOG_NOTICE` | `Credentials updated` | `cid`, `by_cid`, `attributes`. If `suspended` changed, also emit `Credentials suspended` or `Credentials activated`. |
| 46 | `credentials/service.py` | 594 | `LOG_NOTICE` | `Credentials deleted` | `cid`, `by_cid` |
| 47 | `credentials/registration/service.py` | 112 | `LOG_NOTICE` | `Credentials created` | `cid`, `by_cid` |
| 48 | `credentials/registration/service.py` | 273 | `LOG_NOTICE` | `Invitation accepted by a new user` | `cid` |
| 49 | `credentials/registration/service.py` | 334 | `LOG_NOTICE` | `Invitation accepted by an existing user` | `cid`, `t`, `r` |
| 50 | `credentials/change_password/handler.py` | 72 | `LOG_NOTICE` | `Password change failed: Authentication failed` | `cid`, `from_ip` |
| 51 | `credentials/change_password/handler.py` | 84 | `LOG_NOTICE` | `Password change denied: Reusing old passwords is not allowed.` | `cid`, `from_ip` |
| 52 | `credentials/change_password/handler.py` | 97 | `LOG_NOTICE` | `Password change denied: New password too weak.` | `cid`, `from_ip` |
| 53 | `credentials/change_password/handler.py` | 107 | `LOG_NOTICE` | `Password change failed: {ExceptionClass}` | `cid`, `from_ip` |
| 54 | `credentials/change_password/handler.py` | 114 | `LOG_NOTICE` | `Password change successful` | `cid`, `from_ip` |
| 55 | `credentials/change_password/handler.py` | 144 | `LOG_NOTICE` | `Password reset failed: Invalid password reset token` | `from_ip`, `token` |
| 56 | `credentials/change_password/handler.py` | 154 | `LOG_NOTICE` | `Password reset denied: Credentials suspended` | `cid` |
| 57 | `credentials/change_password/handler.py` | 160 | `LOG_NOTICE` | `Password reset denied: New password too weak.` | `cid`, `from_ip` |
| 58 | `credentials/change_password/handler.py` | 170 | `LOG_NOTICE` | `Password reset failed: {ExceptionClass}` | `cid`, `from_ip` |
| 59 | `credentials/change_password/handler.py` | 185 | `LOG_NOTICE` | `Password reset successful` | `cid`, `from_ip` |
| 60 | `client/service.py` | 298 | `LOG_NOTICE` | `Client secret updated.` | `client_id` |

---

*Generated for planning the SeaCat Auth audit logging improvements.*
