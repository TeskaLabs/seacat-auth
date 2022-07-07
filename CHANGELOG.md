# CHANGELOG

## Release candidate

### Breaking changes
- WebAuthn data format changed: Existing WebAuthn credentials are invalidated (#63, PLUM Sprint 220617)

### Refactoring
- Include relaying party ID in WebAuthn storage (#63, PLUM Sprint 220617)
- Dedicated collection for external login credentials (#60, PLUM Sprint 220617)

---


## v22.26

### Breaking changes
- SeaCat API requires authentication with ID token instead of Access token (#39, PLUM Sprint 220520)
- Introspection outputs ID token instead of Access token (#39, PLUM Sprint 220520)
- Roles are no longer included in userinfo or ID token (#50, PLUM Sprint 220603)
- Batman no longer checks role names (#54, PLUM Sprint 220603)
- Public API authenticates by cookie only if no Authorization header is present (#53, PLUM Sprint 220617)

### Fix
- Fix TOTP activation error (#43, PLUM Sprint 220520)
- Fix TOTP status in userinfo (#43, PLUM Sprint 220520)
- Session from ID token bug (82d6787, PLUM Sprint 220520)
- OIDC scope format in token response (b5a18c2, PLUM Sprint 220520)
- Always update the expiration of the whole session group (#44, PLUM Sprint 220520)
- Explicit UTC timezone for all time data in userinfo (#45, PLUM Sprint 220520)
- DuplicateError handling (#47, PLUM Sprint 220603)
- Fix delete and touch session (#55, PLUM Sprint 220617)
- Dict credentials creation complies with policy (b7582e5, PLUM Sprint 220617)
- Fix header enrichment in introspection (f4c95cf, PLUM Sprint 220617)
- Fix external login flow (#58, PLUM Sprint 220617)
- Fix role creation and assignment in old tenants (#57, PLUM Sprint 220617)
- Safer session deserialization (#59, PLUM Sprint 220617)
- Handle malformed cookies (1f6b25e, PLUM Sprint 220617)
- Generate new ID token when extending session (#61, PLUM Sprint 220617)
- Fix ID token exchange in cookie introspection (#61, PLUM Sprint 220617)

### Features
- Structured session list (#30, PLUM Sprint 220520)
- Authentication with ID token (#39, PLUM Sprint 220520)
- Custom credentials data (#40, PLUM Sprint 220520)
- Ensure credentials contain at least an email or a phone (#41, PLUM Sprint 220520)
- Generic MySQL credentials provider (#42, PLUM Sprint 220603)
- Tenant search filter (#49, PLUM Sprint 220603)

### Refactoring
- Authz object no longer contains roles (#50, PLUM Sprint 220603)
- Datetime objects are explicitly UTC-aware (#48, PLUM Sprint 220603)
- RBAC has_resource_access returns boolean (#54, PLUM Sprint 220603)
- Public API authenticates by cookie only if no Authorization header is present (#53, PLUM Sprint 220617)

---


## v22.21

### Fix
- Use datetime.datetime.utcnow (#29, PLUM Sprint 220422)
- After-provisioning cleanup (#33, PLUM Sprint 220506)
- Fix session expiration for back-compat (#34, PLUM Sprint 220506)
- ~~Import ASAB web container (#36, PLUM Sprint 220520)~~(4ade2c60)
- Store login session data in database (#37, PLUM Sprint 220520)

### Features
- Mock mode in SMS provider (#37, PLUM Sprint 220520)

### Refactoring
- Persistent OIDC authorization codes (#25, PLUM Sprint 220408)
- Persistent TOTP secrets (#27, PLUM Sprint 220408)
- Use two-stage docker build (#31, PLUM Sprint 220520)
- Revise default configs and examples (#28, PLUM Sprint 220422)
- Persistent login sessions (#26, PLUM Sprint 220422)
- Session adapter restructured (#32, PLUM Sprint 220506)
- Credentials deletion via credentials service (#33, PLUM Sprint 220506)

---


## v22.16

### Breaking changes
- Tenant name must pass validation before tenant is created (#19, PLUM Sprint 220325)
- Usernames, roles and resources are validated before creation (#22, PLUM Sprint 220325)
- Batman uses resources for access control instead of roles (#21, PLUM Sprint 220408)

### Fixes
- Handle nonexisting provider in M2M introspection (#15, PLUM Sprint 220225)
- Fixed creation policy for M2M provider (#15, PLUM Sprint 220225)
- Automatic tenant and role assignment after tenant creation (#17, PLUM Sprint 220325)
- Remove regex validation for existing roles (#24, PLUM Sprint 220408)

### Features
- Generate MANIFEST.json (#20, PLUM Sprint 220325)
- List resources call now accepts filter string (#21, PLUM Sprint 220408)
- FIDO2/WebAuthn support (login, token management) (#12, PLUM Sprint 220408)

### Refactoring
- Fallback values in ident translation response (#18, PLUM Sprint 220325)
- Tenant name must pass validation before tenant is created (#19, PLUM Sprint 220325)
- Validate usernames, roles and resources before creation (#22, PLUM Sprint 220325)
- Batman uses resources for access control instead of roles (#21, PLUM Sprint 220408)
- Introduce session types (#16, PLUM Sprint 220408)

---


## v22.10

### Features
- ID token contains JWT-encrypted userinfo data (#13, PLUM Sprint 220225)
- Metrics counting active sessions and credentials per provider added (#9, PLUM Sprint 220225)

### Refactoring
- Custom authentication for metrics endpoint (#14, PLUM Sprint 220225)

---


## v22.8

### Breaking changes
- Resource creation endpoint now accepts POST requests (#1, PLUM Sprint 210114)
- Tenant check disabled in introspection (#8, PLUM Sprint 210114)
- "Set tenant data" call now uses a single PUT call (#11, PLUM Sprint 210114)

### Refactoring
- Detailed error messages for cookie domain and session AES key config (#7, PLUM Sprint 210128)
- Set tenant data object with a PUT call (#11, PLUM Sprint 210114)

### Features
- Metrics counting failed and successful logins added (#6, PLUM Sprint 210128)
- Resource description (#1, PLUM Sprint 210114)
- Resource check in introspection (#8, PLUM Sprint 210128)

---


## v22.1.1

### Breaking changes

- Remove `authz:credentials:admin` resource (#5, PLUM Sprint 210114)

### Fixes
- Fixed permissions for tenant assignment (#2, PLUM Sprint 210114)
- Remove default list limits for roles and resources (#4, PLUM Sprint 210114)
- Fix access check in create tenant (#4, PLUM Sprint 210114)

### Features
- Cookie authentication in multi-domain setting (!219, PLUM Sprint 211217)
- Endpoints for single tenant un/assignment (#2, PLUM Sprint 210114)
- Endpoints for single role un/assignment (#3, PLUM Sprint 210114)

### Refactoring
- Remove `authz:credentials:admin` resource (#5, PLUM Sprint 210114)

---


## v22.1

### Breaking changes
- Ident fields config option moved to `[seacatauth:credentials]` section (!208, PLUM Sprint 211023)
- Changed resource requirements for certain tenant, role and credentials API operations (!215, !217, PLUM Sprint 211217)
- External login status parameter renamed (!214, PLUM Sprint 211217)

### Features
- Configurable credentials policy (!208, !213, PLUM Sprint 211203; !218, PLUM Sprint 211217)
- Redirect after external login (!214, PLUM Sprint 211217)

### Fixes
- Catch race condition when extending session (!216, PLUM Sprint 211217)

### Refactoring
- Reduce docker image size (!212, PLUM Sprint 211203)
- Changed resource requirements for certain tenant, role and credentials API operations (!215, !217, PLUM Sprint 211217)

---


## v21.12.1

### Features
- Login with MojeID (!209, PLUM Sprint 211203)

### Fixes
- Remove default limit from tenant search (!210, PLUM Sprint 211203)

---


## v21.12

### Breaking changes
- Cookie introspection removes Seacat cookie from the request (!196, PLUM Sprint 211023)
- Renamed password reset config option (!203, PLUM Sprint 211119)
- Removed support for loading roles from file (!203, PLUM Sprint 211119)

### Features
- Cookie introspection exchanges cookie for Bearer token (!196, PLUM Sprint 211023)
- Tenant object contains the ID of its creator (!198, PLUM Sprint 211023)
- M2M credentials and M2M introspection endpoint (!187, PLUM Sprint 211023)
- Tenant search returns the number of tenants (!200, PLUM Sprint 211023)
- Include editable fields in provider info (!201, PLUM Sprint 211023)
- Translation of credential IDs to usernames (!202, PLUM Sprint 211119)
- Key-value storage in tenant object (!204, PLUM Sprint 211119)
- Endpoint for app features (!199, PLUM Sprint 211119)
- Login with external OAuth2 (Google, Github, Office365) (!199, PLUM Sprint 211119)

### Refactoring
- Session cookie value is encrypted on backend (!196, PLUM Sprint 211023)
- Specific error responses from password reset (!203, PLUM Sprint 211119)
- Removed support for loading roles from file (!203, PLUM Sprint 211119)
- Change URL for external login deletion (!207, PLUM Sprint 211119)

---


## v21.11

### Breaking changes
- TOTP activation now requires verification with OTP (!185, PLUM Sprint 210924)
- Require OTP by default if possible (!189, PLUM Sprint 211011)
- Two separate containers for public and non-public endpoints (!190, PLUM Sprint 211011)
- API web container does not support cookie authentication (!190, PLUM Sprint 211011)

### Features
- TOTP activation now requires verification with OTP (!185, PLUM Sprint 210924)
- Listing credentials supports filtering by tenant (!191, PLUM Sprint 211011)
- Public endpoint for deleting user's own sessions (!192, PLUM Sprint 211011)
- Endpoint for enforcing password reset (!193, PLUM Sprint 211011)
- Public endpoint for updating own credentials (!194, PLUM Sprint 211022)
- Add resources in Nginx introspection calls (!195, PLUM Sprint 211022)

### Fixes
- Fixed duplicate error handling in credentials update (!188, !197, PLUM Sprint 211011)

### Refactoring
- Require OTP by default if possible (!189, PLUM Sprint 211011)
- Separate web container for public endpoints (!190, PLUM Sprint 211011)

---


## v21.10

### Breaking changes
- TOTP endpoints behavior changed (!175, PLUM Sprint 210827)
- Encryption key must be specified in config (!181, PLUM Sprint 210910)
- Obsolete endpoint `/public/password` removed (!183, PLUM Sprint 210924)

### Features
- Cookie expiration is now set to maximum session age (!173, PLUM Sprint 210827)
- Listing credentials supports filtering by role (!168, PLUM Sprint 210827)
- Enforce login factors at `/openidconnect/authorize` (!174, PLUM Sprint 210827)
- ~~RBAC endpoints now have a public alias (!177, PLUM Sprint 210827)~~(!182, PLUM Sprint 210910)
- ~~RBAC check of multiple resources at once (!177, PLUM Sprint 210827)~~(!182, PLUM Sprint 210910)
- Encrypt sensitive session fields (!181, PLUM Sprint 210910)
- Successful and failed password change attempts are logged in the audit (!183, PLUM Sprint 210924)
- New `select_account` option in `/openidconnect/authorize` (!186, PLUM Sprint 210924)

### Fixes
- Respond 401 to login with missing credentials (!180, PLUM Sprint 210827)
- Use double encoding for redirect URI in factor setup redirect (!184, PLUM Sprint 210924)

### Refactoring
- Hide redundant login descriptors (!174, PLUM Sprint 210827)
- Disallow direct updates of sensitive credentials fields (!176, PLUM Sprint 210910)
- Two-step TOTP activation (!175, PLUM Sprint 210910)
- Last login and available factors now in userinfo response (!181, PLUM Sprint 210910)

---


## 21.08.00

### Breaking changes
- All `/session...` and `/sessions...` API calls are now superuser-only (!159, PLUM Sprint 210716)
- Config option `touch_extension_ratio` renamed to `touch_extension` (!171, PLUM Sprint 210827)

### Features
- `GET /sessions/{credentials_id}` lists all the sessions of a given credentials (!159, PLUM Sprint 210716)
- Introducing configurable maximum session age (!163, PLUM Sprint 210716)
- Introducing configurable touch extension ratio (!163, PLUM Sprint 210716)
- Log LDAP authentication failure (!162, PLUM Sprint 210716)
- Log ident on authentication failure (!162, PLUM Sprint 210716)
- Implement `list` and `get` methods of `DictCredentialsProvider` (!164, PLUM Sprint 210716)
- Unit tests for RBAC resource access method (!165, PLUM Sprint 210813)
- Allow user to disable TOTP via `PUT /public/unset-otp` (!166, PLUM Sprint 210813)
- Get TOTP activation status via `GET /public/otp` (!170, PLUM Sprint 210827)

### Fixes
- Fix "fake login session" functionality with new login descriptors (!157, PLUM Sprint 210702)
- Propagate optional query params from openidconnect/authorize to login (!161, PLUM Sprint 210716)
- Handle fallback login descriptor properly when URL descriptors are provided (!162, PLUM Sprint 210716)
- Always check if user is suspended when authenticating (!166, PLUM Sprint 210813)
- Dictionary (+provisioning) credentials provider uses correct password field in authentication (!167, PLUM Sprint 210813)

### Refactoring
- Update jwcrypto to v0.9.1 (!158, PLUM Sprint 210702)
- Updated documentation (!160, PLUM Sprint 210716)
- All `/session...` and `/sessions...` API calls are now superuser-only (!159, PLUM Sprint 210716)
- Core session object fields renamed with underscore notation for consistency (!163, PLUM Sprint 210716)
- Updated `create` and `update` methods of `DictCredentialsProvider` (!164, PLUM Sprint 210716)
- Allow session touch extension to be either a ratio or absolute duration (!171, PLUM Sprint 210827)

---


## 21.07.00

### Breaking changes

- Password reset expiration config key renamed to `expiration` and its value is now expressed as timedelta string (!103, PLUM Sprint 210904)
- `GET /provider` endpoint renamed to `GET /providers` (!105, PLUM Sprint 210905)
- `PUT /role/{tenant}/{role_name}` now requires tenant admin access (!110, PLUM Sprint 210905)
- All non-public endpoints now require authenticated access by default (!116, PLUM Sprint 210906)
- All non-public endpoints now require authorized access by default (!125, PLUM Sprint 210906)
- `PUT /roles/{tenant}/{credentials_id}` now requires tenant admin access (!113, PLUM Sprint 210905)
- Only superuser can assign global roles (!113, PLUM Sprint 210905)
- Changed the base URL for password reset (!135, PLUM Sprint 210521)
- `DELETE /role/{tenant}/{role}` requires tenant admin access (!143, PLUM Sprint 210522)
- `DELETE /tenant/{tenant}` requires superuser access (!144, PLUM Sprint 210522)
- `DELETE /session/{session_id}` requires superuser access (!145, PLUM Sprint 210522)
- Section `[sessions]` renamed to `[seacatauth:session]` and `expiration` option now expects 
  a "timedelta" string (!153, PLUM Sprint 210618)
- Login factor type "smslogin" renamed to "smscode" (!156, PLUM Sprint 210702)

### Features

- Configurable login descriptors (!87, PLUM Sprint 210904)
- New login method: SMS login (!87, PLUM Sprint 210904)
- Configurable network timeout in LDAPCredentialsProvider (!98, PLUM Sprint 210904)
- Session expiration time in userinfo response (!102, PLUM Sprint 210904)
- Automatic admin assignment on tenant creation (!101, PLUM Sprint 210904)
- Configurable password reset request expiration in `PUT /password` call (!103, PLUM Sprint 210904)
- Server-side filtering in `LDAPCredentialsProvider` (!106, PLUM Sprint 210905)
- Introducing `authz:tenant:admin` resource, required for tenant administration operations (!110, PLUM Sprint 210905)
- Expirable login sessions (!112, PLUM Sprint 210905)
- The `GET /rbac/...` endpoints can now authorize any resource (!114, PLUM Sprint 210905)
- All non-public endpoints now require authenticated access (!116, PLUM Sprint 210906)
- Add roles in Nginx introspection calls (!119, PLUM Sprint 210906)
- All non-public endpoints can now require resource-authorized access (!125, PLUM Sprint 210906)
- Login descriptor that the user authenticated with is stored in `Session.LoginDescriptor` (!128, PLUM Sprint 210906)
- `GET /openidconnect/userinfo` includes login factors and login descriptor that the user authenticated with (!128, !131, PLUM Sprint 210906)
- Introspection can now add login factors or login descriptor to request headers (!131, PLUM Sprint 210521)
- Request login descriptors via URL query (!133, PLUM Sprint 210521)
- Pass login descriptors from `openidconnect/authorize` to login page (!138, PLUM Sprint 210521)
- `GET /rbac/*/{resource}` checks the presence of a resource under any tenant (!141, PLUM Sprint 210522)
- Adding `DELETE /sessions` and `DELETE /sessions/{credentials_id}` for bulk session deletion (!145, PLUM Sprint 210522)
- Login descriptors can now have several `LoginFactor` OR-groups (!149, PLUM Sprint 210618)
- Introducing `XHeaderFactor` (!151, PLUM Sprint 210618)
- Added documentation for SCA deployment and provisioning (!152, PLUM Sprint 210618)
- Introspection calls now automatically refresh the session (!153, PLUM Sprint 210618)
- Unassign roles when unassigning tenants (!154, PLUM Sprint 210702)

### Fixes

- `PUT /public/logout` now responds with `400` to missing or invalid cookies (!100, PLUM Sprint 210904)
- Combining results from two different providers on the same page in `CredentialsHandler.list_credentials` (!106, PLUM Sprint 210905)
- Fixed tenant access denial to superuser (!110, PLUM Sprint 210905)
- Fixed incorrect method reference in `TenantHandler.delete()` (!110, PLUM Sprint 210905)
- Updated TLS setting in `LDAPCredentialsProvider.authenticate()` (!117, PLUM Sprint 210906)
- Disable SMS login if user has no phone number (!121, PLUM Sprint 210906)
- `GET /tenant` is now available without authentication (!122, PLUM Sprint 210906)
- Catch exceptions raised in SMS login process (!124, PLUM Sprint 210906)
- `GET /rbac/...` endpoints are now available without authn/z (!126, PLUM Sprint 210906)
- `POST /cookie/nginx` endpoints are now available without authn/z (!129, PLUM Sprint 210906)
- Fixed admin role assignment in tenant creation (!132, PLUM Sprint 210521)
- Avoid producing empty SMS messages (!137, PLUM Sprint 210521)
- JWCrypto version locked at 0.8 to fix login prologue (!140, PLUM Sprint 210522)
- On provisioning start, check for existing provisioning tenant to avoid duplicate error (!146, PLUM Sprint 210522)
- Handle `prompt=login` parameter properly at `openidconnect/authorize` endpoint (!150, PLUM Sprint 210618)
- Remove invalid tenants from scope when setting roles (!155, PLUM Sprint 210702)

### Refactoring

- Access control functions refactored into `access_control` decorator (!99, 
  !107, !110, PLUM Sprint 210905)
- Credential providers can be explicitly ordered via configuration (!105, PLUM Sprint 210905)
- Provisioning mode now also manages a provisioning tenant (!108, PLUM Sprint 210905)
- Added config options for `tls_require_cert` in LDAPCredentialsProvider (!109, PLUM Sprint 210905)
- `PUT /role/{tenant}/{role_name}` now requires tenant admin access (!110, PLUM Sprint 210905)
- Limit the number of login attempts (!111, PLUM Sprint 210905)
- Removed obsolete `seacatauth.sms` and `seacatauth.smtp` modules (!115, PLUM Sprint 210906)
- Only superuser can assign global roles (!113, PLUM Sprint 210905)
- Changed the base URL for password reset (!135, PLUM Sprint 210521)
- Default message templates are included in Docker image (!142, PLUM Sprint 210522)
- `DELETE /role/{tenant}/{role}` first removes all assignments of `{tenant}/{role}` 
  before deleting the role (!143, PLUM Sprint 210522)
- `DELETE /tenant/{tenant}` first removes all linked roles and assignments (!144, PLUM Sprint 210522)
- Introducing `LoginFactor` and `LoginDescriptor` classes (!149, PLUM Sprint 210618)
- Section `[sessions]` renamed to `[seacatauth:session]` and `expiration` option now expects 
  a "timedelta" string (!153, PLUM Sprint 210618)
- Login factor type "smslogin" renamed to "smscode" (!156, PLUM Sprint 210702)
