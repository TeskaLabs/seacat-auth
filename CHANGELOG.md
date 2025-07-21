# CHANGELOG

## v25.26

### Pre-releases
- v25.26-alpha5
- v25.26-alpha4
- v25.26-alpha3
- v25.26-alpha2
- v25.26-alpha1

### Breaking changes
- Admin tenant invitation path changed to `/admin/tenant/{tenant}/invite`.
  Common user tenant invitation path changed to `/account/tenant/{tenant}/invite` (#501, v25.13-alpha5)

### Fixes
- Add default value for passwordlink in credentials creation (#494, v25.26-alpha2)
- Fix ASAB version printer (#492, v25.26-alpha1)
- Fix credentials search - Client provider error (#489, v25.26-alpha1)

### Features
- New resource ID `seacat:client:apikey:manage` for client API key management (#488, v25.26-alpha4)
- Prefix client API with /admin (#488, v25.26-alpha4)
- Prefix credentials API with /admin (#493, v25.26-alpha3)

### Refactoring
- Adapt to ASAB tenant mode (#501, v25.26-alpha5)

---


## v25.13

### Pre-releases
- v25.13-alpha15
- v25.13-alpha14
- v25.13-alpha13
- v25.13-alpha12
- v25.13-alpha11
- ~~v25.13-alpha10~~
- v25.13-alpha9
- v25.13-alpha8
- v25.13-alpha7
- v25.16-alpha
- v25.13-alpha6
- v25.13-alpha5
- v25.13-alpha4
- v25.13-alpha3
- v25.13-alpha2
- v25.13-alpha1

### Breaking changes
- Dropped Python 3.10 support (#465, v25.13-alpha4)

### Fix
- Do not sync deleted credentials with Elasticsearch/Kibana (#483, v25.13-alpha14)
- Fix attribute error in webauthn error log (#481, v25.13-alpha12)
- Fix Dockerfile with venv (#480, v25.13-alpha11)
- Fix external login attribute error (#476, v25.13-alpha8)
- Respond with HTTP 200 when new user is created but the password reset email fails (#477, v25.13-alpha7)
- Update Batman after successful credentials registration (#472, v25.16-alpha)

### Features
- Admin API for managing TOTP and WebAuthn credentials (#486, v25.13-alpha15)
- Make `global_only` a persistent resource attribute (#483, v25.13-alpha14)
- API key support (#469, v25.13-alpha13)
- OAuth 2.0 Client credentials flow (#469, v25.13-alpha13)
- Upgrade python to 3.12 and alpine to 3.21 (#479, v25.13-alpha10)
- Make ES role monitoring_user available via resource elasticsearch:monitoring (#478, v25.13-alpha9)
- Support for `tls_certfile` and `tls_keyfile` in LDAP credentials provider (#468, v25.13-alpha6)
- Only clients with `seacatauth_credentials: True` have credentials API (#467, v25.13-alpha5)
- Implement max_age authorization parameter (#458, v25.13-alpha3)
- Client credentials provider (#462, v25.13-alpha2)

### Refactoring
- Define and use OAuth2 constants (#465, v25.13-alpha4)
- Common method for converting credentials ID to inner database ID (#461, v25.13-alpha1)

---


## v25.05

### Pre-releases
- v25.05-alpha19
- v25.05-alpha18
- v25.05-alpha17
- v25.05-alpha16
- v25.05-alpha15
- v25.05-alpha14
- v25.05-alpha13
- v25.05-alpha12
- v25.05-alpha11
- v25.05-alpha10
- v25.05-alpha9
- v25.05-alpha8
- v25.05-alpha7
- v25.05-alpha6
- v25.05-alpha5
- v25.05-alpha4
- v25.05-alpha3
- v25.05-alpha2
- v25.05-alpha1

### Fix
- Fix authorization in accepting an invitation as an existing user (#460, v25.05-alpha19)
- Fix access check for creating a global role (#457, v25.05-alpha18)
- Fix access check for creating a tenant (#457, v25.05-alpha18)
- Fix email template parameters (#456, v25.05-alpha17)
- Handle FIDO MDS ClientConnectionError (#438, v25.05-alpha1)

### Features
- Superuser always receives invitation and reset codes in response (#450, v25.05-alpha15)
- Store invitation codes as hashes (#450, v25.05-alpha15)
- Dedicated resource ID for tenant creation (#454, v25.05-alpha14)
- Support ASAB Iris for sending emails (#442, v25.05-alpha5)
- Configurable default tenant roles (#436, v25.05-alpha3)
- Provisioning service initialization uses system Session object (#439, v25.05-alpha2)

### Refactoring
- Use ASAB AuthService and TenantService for API authorization (#440, v25.05-alpha16)
- Rename email template parameters (#451, v25.05-alpha13)
- Always initialize tenant provider (#449, v25.05-alpha12)
- Separate JSON schemas (#448, v25.05-alpha11)
- Remove obsolete back-compat endpoints (#447, v25.05-alpha10)
- Replace resource ID literals with constants (#446, v25.05-alpha9)
- Refactor name proposer service into a function (#445, v25.05-alpha8)
- Clean up imports and code style (#444, v25.05-alpha7)
- Rename SessionAdapter to Session and move to seacatauth.models (#443, v25.05-alpha6)
- Refactor communication module, merge message builders into communication providers (#442, v25.05-alpha5)
- Remove session adapter's dependency on session service (#441, v25.05-alpha4)

---


## v24.45

### Compatibility
- ASAB WebUI v24.47 and later

### Pre-releases
- v24.45-alpha7
- v24.45-alpha6
- v24.45-alpha5
- v24.45-alpha4
- v24.45-alpha3
- v24.45-alpha2
- v24.45-alpha1

### Fix
- Remove expires_in from token response for anonymous sessions (#434, v24.45-alpha6)
- Catch and log ldap.INVALID_CREDENTIALS (#431, v24.45-alpha4)
- Fix role error in provisioning startup (#428, v24.45-alpha2)
- Log more details when message delivery fails (#427, v24.45-alpha1)

### Features
- Do not issue refresh token when maximum session age is reached (#435, v24.45-alpha7)
- Nicer message when message delivery fails (#432, v24.45-alpha5)
- Do not automatically assign tenant to its creator (#429, v24.45-alpha3)

---


## v24.39

### Pre-releases
- v24.39-alpha3
- v24.39-alpha2
- v24.39-alpha1

### Fix
- Avoid logging stacktrace when LDAP credentials server is down (#426, `v24.39-alpha3`)
- Log the credentials out when they are suspended (#425, `v24.39-alpha2`)
- Fix credentials custom data editing (#424, `v24.39-alpha1`)

---


## v24.36

### Pre-releases
- v24.36-beta
- v24.36-alpha5
- v24.36-alpha4
- v24.36-alpha3
- ~~v24.36-alpha2~~
- v24.36-alpha1
- v24.29-alpha7
- v24.29-alpha6

### Fix
- Fix handling of empty filter in LDAP credentials provider (#421, `v24.36-alpha4`)
- Upgrade CI/CD action versions (#418, `v24.36-alpha3`)
- Sort assigned tenants and roles alphabetically (#417, `v24.36-alpha3`)
- Do not check tenant existence when unassigning tenant (#415, `v24.29-alpha8`)
- Hotfix: Session expiration in userinfo must match access token expiration (#414, `v24.29-alpha7`)

### Features
- Improve the default configuration of LDAP credentials provider (#422, `v24.36-alpha5`)
- Duplicating roles (#416, `v24.36-alpha1`)
- Run Batman with warning when there is no ElasticSearch URL (#413, `v24.29-alpha6`)

### Refactoring
- Refactor LDAP credentials provider (#422, `v24.36-alpha5`)

---


## v24.29

### Pre-releases
- v24.29-beta2
- v24.29-beta
- v24.29-alpha5
- v24.29-alpha4
- v24.29-alpha3
- v24.29-alpha2
- v24.29-alpha1

### Fix
- Non-editable items are marked with read_only flag (#411, `v24.29-alpha5`)
- Handle session decryption error (#410, `v24.29-alpha2`)

### Features
- Disable editing of managed resources and clients (#409, `v24.29-alpha4`)
- Global roles propagated to tenants (#395, `v24.29-alpha3`)
- Sort clients alphabetically by client name (#408, `v24.29-alpha2`)
- Print ASAB version during Docker build (#406, `v24.29-alpha1`)

---


## v24.20

### Pre-releases
- `v24.20-alpha14`
- `v24.20-alpha13`
- `v24.20-alpha12`
- `v24.20-alpha11`
- `v24.20-alpha10`
- `v24.20-alpha9`
- `v24.20-alpha8`
- `v24.20-alpha7`
- `v24.20-alpha6`
- `v24.20-alpha5`
- `v24.20-alpha4`
- `v24.20-alpha3`
- `v24.20-alpha2`
- `v24.20-alpha1`

### Breaking changes
- Removed total item count from credential list response (#391, `v24.20-alpha12`, Compatible with Seacat Admin WebUI v24.19-alpha28 and later)
- External login endpoints changed (#384, `v24.20-alpha9`)
- Default password criteria are more restrictive (#372, `v24.20-alpha1`, Compatible with Seacat Auth Webui v24.19-alpha and later, Seacat Account Webui v24.08-beta and later)

### Fix
- Fix nginx oauth introspection for self-encoded (algorithmic) sessions (#405, `v24.20-alpha14`)
- Fix token request for self-encoded (algorithmic) sessions (#404, `v24.20-alpha13`)
- Fix credential search performance (#391, `v24.20-alpha12`)
- Fix AttributeError in credentials update (#399, `v24.20-alpha11`)
- Catch token decoding errors when finding sessions (#397, `v24.20-alpha10`)
- Properly encrypt cookie value in session update (#394, `v24.20-alpha8`)
- Properly parse URL query before adding new parameters (#393, `v24.20-alpha8`)
- Delete client cookie on introspection failure (#385, `v24.20-alpha6`)
- Extend session expiration at cookie entrypoint (#383, `v24.20-alpha5`)
- Do not log failed LDAP login as error (#381, `v24.20-alpha4`)
- Properly handle Argon2 verification error in login call (#378, `v24.20-alpha3`)

### Features
- Log login factor verification failure (#402, `v24.20-alpha12`)
- External login with dynamic redirection (#384, `v24.20-alpha9`)
- Custom response codes for tenant-related authorization errors (#392, `v24.20-alpha8`)
- Implement OAuth refresh tokens (#358, `v24.20-alpha2`)
- Configurable password criteria (#372, `v24.20-alpha1`)

### Refactoring
- Expected client ID is optional for authentication (#390, `v24.20-alpha8`)
- Move SSO session creation into session service (#387, `v24.20-alpha8`)
- Refactor duplicate code in session build (#386, `v24.20-alpha7`)

---


## v24.17

### Pre-releases
- `v24.17-alpha9`
- `v24.17-alpha8`
- `v24.17-alpha7`
- `v24.17-alpha6`
- `v24.17-alpha5`
- `v24.17-alpha4`
- `v24.17-alpha3`
- `v24.17-alpha2`
- `v24.17-beta1`
- `v24.17-alpha1`

### Fix
- Fix AttributeError in failed login (#376, `v24.17-alpha9`)
- Deny password change when old password verification fails (#374, `v24.17-alpha7`)
- Authorize into last active tenant (#373, `v24.17-alpha6`)
- Default provisioning tenant name mst pass validation (#368, `v24.17-alpha4`)
- Fix the initialization and updating of built-in resources (#363, `v24.06-alpha15`)
- Fix searching credentials with multiple filters (#362, `v24.06-alpha14`)

### Features
- Hash passwords using argon2 instead of bcrypt (#375, `v24.17-alpha8`)
- Improve resource sorting and filtering (#370, `v24.17-alpha3`)
- User invitations are enabled by default (#367, `v24.17-alpha2`)
- When invitation cannot be created because the user already exists, the invitation is re-sent (#364, `v24.17-alpha1`)
- When no communication channel is configured, invitation and password reset URLs are returned in admin responses (#364, `v24.17-alpha1`)
- Listing assigned tenants and roles no longer requires resource authorization (#348, `v24.06-alpha13`)
- List credentials from authorized tenant only (#348, `v24.06-alpha13`)

### Refactoring
- Consistent use of item-specific not-found exceptions (#371, `v24.17-alpha5`)
- Deprecate passlib (#368, `v24.17-alpha4`)
- Utility functions for password verification (#368, `v24.17-alpha4`)

---


## v24.06

### Pre-releases
- `v24.06-alpha15`
- `v24.06-alpha14`
- `v24.06-alpha13`
- `v24.06-alpha12`
- `v24.06-alpha11`
- `v24.06-alpha10`
- `v24.06-beta3`
- `v24.06-alpha9`
- `v24.06-alpha8`
- `v24.06-beta2`
- `v24.06-alpha7.2`
- `v24.06-beta`
- `v24.06-alpha6`
- `v24.06-alpha5`
- `v24.06-alpha4`
- `v24.06-alpha3`
- `v24.06-alpha2`
- `v24.06-alpha1`

### Breaking changes
- Credentials list returns only the members of the currently authorized tenant (#348, `v24.06-alpha13`)
- Disable special characters in tenant ID (#349, `v24.06-alpha6`)

### Fix
- Better TOTP error responses (#352, `v24.06-alpha10`)
- Fix resource editability (#355, `v24.06-alpha9`)
- Make FIDO MDS request non-blocking using TaskService (#354, `v24.06-alpha8`)
- Improve error handling in FIDO MDS (#351, `v24.06-alpha5`)
- Fix typo in last login endpoint path (#346, `v24.06-alpha4`)
- Fix the initialization of NoTenantsError (#346, `v24.06-alpha2`)

### Features
- Client cache (#361, `v24.06-alpha13`)
- Update OpenAPI specs (#360, `v24.06-alpha12`)
- Client secret management (#359, `v24.06-alpha11`)
- External login provider label contains just the display name (#352, `v24.06-alpha10`)
- ElasticSearch index and Kibana space authorization (#353, `v24.06-alpha7.2`)
- Disable special characters in tenant ID (#349, `v24.06-alpha6`)
- New paths for account management endpoints (#343, `v24.06-alpha3`)
- Deprecate "seacat:access" resource ID (#341, `v24.06-alpha1`)

---


## v23.47

### Pre-releases
- `v23.47-beta2`
- `v23.47-alpha7`
- `v23.47-alpha6`
- `v23.47-beta`
- `v23.47-alpha5`
- `v23.47-alpha4`
- `v23.47-alpha3`
- `v23.47-alpha2`
- `v23.47-alpha`

### Breaking changes
- Config section 'batman:elk' renamed to 'batman:elasticsearch' (#333, `v23.47-alpha5`)
- Public URL config changed (#328, #330, `v23.47-alpha4`)
- Remove access token from websocket protocol header during introspection (#324, `v23.47-alpha2`)
- Batman for Kibana now also requires `kibana_url` (#281, `v23.47-alpha`)
- Batman does no longer create Seacat resources from all Kibana roles (#281, `v23.47-alpha`)
- ~~Config section 'batman:elk' renamed to 'batman:kibana' (#281, `v23.47-alpha`)~~

### Fix
- Impersonation error handling (#339, `v23.47-alpha7`)
- Initialize batman service regardless of configuration (#337, `v23.47-alpha7`)
- Well-known endpoints in the private container are available without auth (#335, `v23.47-alpha6`)
- Check suspended credentials before login and password reset (#334, `v23.47-alpha6`)
- Fixed Batman Kibana component initialization (#333, `v23.47-alpha5`)

### Features
- Access token Batman introspection (#333, `v23.47-alpha5`)
- Replace audit service with audit logger (#329, `v23.47-alpha5`)
- Hash password reset codes in the database (#329, `v23.47-alpha5`)
- Batman configuration for Kibana can be also loaded from the `[elasticsearch]` section (#326, `v23.47-alpha4`)
- Public URL config now requires only one option in canonical deployments (#328, #330, `v23.47-alpha4`)
- Kibana spaces and roles are now synchronized with Seacat tenants (#281, `v23.47-alpha`)

### Refactoring
- Modular login session (#336, `v23.47-alpha7`)
- Multiple ElasticSearch node URLs are supported (#326, `v23.47-alpha4`)
- Separate login factors in session object (#325, `v23.47-alpha3`)

---


## v23.44-beta

### Pre-releases
- `v23.44-alpha6`
- `v23.44-alpha5`
- `v23.44-alpha4`
- `v23.44-alpha3`

### Breaking changes
- Dropped support for authorize query params `ldid` and `expiration` (#296, PLUM Sprint 231006)

### Fix
- Fix client cookie introspection (#322, INDIGO Sprint 231110, `v23.44-alpha5`)
- Handle missing webauthn data in login request (#314, INDIGO Sprint 231027, `v23.44-alpha4`)
- Fix default authorize parameter values when redirecting (#313, PLUM Sprint 231020)

### Features
- Log successful authorization requests (#323, INDIGO Sprint 231110, `v23.44-alpha6`)
- Lower client ID length limit (#322, INDIGO Sprint 231110, `v23.44-alpha5`)
- Include client ID and scope in session detail (#318, INDIGO Sprint 231027, `v23.44-alpha4`)
- Reduce grafana sync frequency (#317, INDIGO Sprint 231027, `v23.44-alpha3`)
- Authorization for websocket requests (#300, PLUM Sprint 231006)
- Silence stable log messages (#312, PLUM Sprint 231006)
- External login registration webhook (#286, PLUM Sprint 231006)
- OAuth Authorize ignores all unknown parameters (#296, PLUM Sprint 231006)
- Log failure reasons in introspection and authorization flow (#315, INDIGO Sprint 231027)

### Refactoring
- Do not log "unhappy flow" as errors (#315, INDIGO Sprint 231027)

---


## v23.42-beta

### Breaking changes
- NGINX introspection endpoints paths changed and moved to private API (#301, #311, PLUM Sprint 231006)

### Fix
- Preserve nonce when redirecting to login (#294, PLUM Sprint 230908, @elpablos)
- Allow username for WebAuthn credentials username (#297, PLUM Sprint 230908)
- NGINX introspection endpoints moved to private API (#301, #311, PLUM Sprint 231006)

### Features
- Login with AppleID (#293, PLUM Sprint 230908, @filipmelik)
- Webauthn authenticator metadata (#256, PLUM Sprint 230908)
- Configurably disable auditing of anonymous sessions (#304, PLUM Sprint 231006)

---


## v23.39-beta

### Fix
- Fix private key provisioning (#267, @vosmol)
- Handle missing fields in credential creation (#290, PLUM Sprint 230908)
- Remove upsertor from audit service (#269, PLUM Sprint 230908)

### Features
- Support tenant search in old MongoDB versions (#268, PLUM Sprint 230908)
- Public invitations to tenant (#261, PLUM Sprint 230908)
- Human-readable tenant label (#285, PLUM Sprint 230908)
- Log failed password change requests (#291, PLUM Sprint 230908)
- Get Github user email address (#289, PLUM Sprint 230908)
- External login ID token validation (#292, PLUM Sprint 230908)
- Log reasons for introspection failure (#299, PLUM Sprint 231006)

---


## v23.37-beta

### Breaking changes
- Config option `sender_email_address` is now called `from` (#257, PLUM Sprint 230825)
- Invalid redirect URI or client ID in Authorize request results in an error response without redirect (#266, PLUM Sprint 230908)
- Config section `[seacat_auth]` renamed to `[seacatauth]` (#266, PLUM Sprint 230908)

### Fix
- Add `id_token_signing_alg_values_supported` in OIDC discovery (#260)
- Add support for `nonce` authorize parameter (#263, PLUM Sprint 230908)
- Handle special characters in login ident (#264, PLUM Sprint 230908)

### Features
- Unified SMTP config (#257, PLUM Sprint 230825)
- Endpoint for pruning old audit entries (#259, PLUM Sprint 230825)
- Algorithmic (stateless) anonymous sessions (#232, PLUM Sprint 230825)
- Initialize Zookeeper service (#265, PLUM Sprint 230908)
- Initialize Sentry service (#262, PLUM Sprint 230908)
- Config option to disable all redirect URI validations (#266, PLUM Sprint 230908)

### Refactoring
- Last login info moved to a dedicated collection (#259, PLUM Sprint 230825)

---


## v23.36-beta

### Fix
- Default OIDC Issuer name set to the value of PUBLIC_AUTH_API (#249, PLUM Sprint 230811)
- Re-lock webauthn package version (#258, PLUM Sprint 230811)

### Features
- Role list supports searching by name (#247, PLUM Sprint 230811)
- OIDC/OAuth discovery endpoint (#249, PLUM Sprint 230811)
- Token revocation endpoint (#249, PLUM Sprint 230811)
- Added /.well-known/jwks.json endpoint (#249, PLUM Sprint 230811)

---


## v23.33-beta

### Features
- Upgrade to Alpine 3.18 and Python 3.11 (#245, PLUM Sprint 230728)

### Refactoring
- ELK Batman uses ASAB SSLContextBuilder (#244, PLUM Sprint 230728)

---


## v23.32-beta

### Breaking changes
- Seacat Auth listens on ports 3081 and 8900 by default (#230, PLUM Sprint 230714)

### Fix
- Validate client session expiration (#237, PLUM Sprint 230714)
- Add `editable` field in provider info (#238, PLUM Sprint 230728)
- Fix resource rename flow (#239, PLUM Sprint 230728)

### Features
- Seacat Auth listens on ports 3081 and 8900 by default (#230, PLUM Sprint 230714)
- Add SSL and API key support in ELK batman (#241, GREY Sprint 230714)

---


## v23.30-beta

### Breaking changes
- Old Batman sessions are invalidated (#230, PLUM Sprint 230630)
- Expiration removed from login query params (#233, PLUM Sprint 230630)

### Fix
- Root session must be as long as its longest subsession (#228, PLUM Sprint 230630)
- Webauthn `user_name` can be either email address or phone number (#229, PLUM Sprint 230630)
- Batman token uses native ASAB Storage encryption (#230, PLUM Sprint 230630)
- Expiration removed from login query params (#233, PLUM Sprint 230630)

### Features
- Added alternative POST endpoint for Batman introspection (#230, PLUM Sprint 230630)

---


## v23.27-beta

### Breaking changes
- Batman auth flow merged with cookie auth flow (#216, PLUM Sprint 230616)
- `aes_key` option has been moved to `[asab:storage]` section (#221, PLUM Sprint 230616)
- Last login info is no longer included in userinfo and credentials detail (#219, PLUM Sprint 230616)

### Fix
- Fix broken webauthn dependency (#227, PLUM Sprint 230630)

### Features
- Configurable anonymous session expiration (#217, PLUM Sprint 230616)
- Update modtime of active sessions (#226, PLUM Sprint 230616)

### Refactoring
- ~~Bump Python version to 3.11 and Alpine to 3.18 (#215, PLUM Sprint 230602)~~(d415691)
- Batman auth flow merged with cookie auth flow (#216, PLUM Sprint 230616)
- Clear expired objects during housekeeping (#218, PLUM Sprint 230616)
- `aes_key` option has been moved to `[asab:storage]` section (#221, PLUM Sprint 230616)
- Reduce last login reads (#219, PLUM Sprint 230616)

---

## v23.23-beta

### Fix
- Fix login redirect at the authorize endpoint (#203, PLUM Sprint 230509)
- Do not assign the tenant "*" in bulk assignment (#209, PLUM Sprint 230519)
- If track id cannot be transferred, generate a new one instead of returning error (#214, PLUM Sprint 230602)

### Features
- User impersonation (#188, PLUM Sprint 230509)
- Configurable client session expiration (#204, PLUM Sprint 230509)
- Additional TLS options in LDAP provider (#208, PLUM Sprint 230519)
- Impersonation REST API (#210, PLUM Sprint 230602)

### Refactoring
- Allow impersonating superuser credentials, but exclude the superuser resource (#210, PLUM Sprint 230602)
- Session performance improvement (#211)

---


## v23.18-beta

### Breaking changes
- In resource list, the `include_deleted` and `exclude_global_only` params are replaced by `exclude` param (#196, PLUM Sprint 230421)
- Cookie authorize requests require that cookie_entry_uri be configured (#188, PLUM Sprint 230421)
- The state-redirect mechanism in cookie flow has been removed (#188, PLUM Sprint 230421)

### Fix
- Fix provisioning initialization (#195, PLUM Sprint 230412)
- Fix request access control attributes and methods (#197, PLUM Sprint 230421)
- Reintroduce metrics (#198, PLUM Sprint 230421)
- Allow batman to be configured without basic auth (#199, PLUM Sprint 230421)
- Include client cookie name in client detail (#200, PLUM Sprint 230421)
- Fix cookie entrypoint when no webhook is configured (#184, PLUM Sprint 230421)

### Features
- Filter resource list by resource type using the `exclude` query parameter (#196, PLUM Sprint 230421)
- Cookie entrypoint webhook for setting custom response headers (#188, PLUM Sprint 230421)

### Refactoring
- Each client has their unique cookie name (#188, PLUM Sprint 230421)

---


## v23.16-beta

### Breaking changes
- Introspection requests require client_id in the query (#156, PLUM Sprint 230324)
- Every cookie introspection should be paired with a cookie entrypoint (#156, PLUM Sprint 230324)
- Bouncer module replaced by cookie entrypoint (#156, PLUM Sprint 230324)
- Dropped support for custom cookie domains in the configuration (#156, PLUM Sprint 230324)
- External login status messages changed (#185, PLUM Sprint 230324)
- Bulk-unassign tenants using "UNASSIGN-TENANT" (#189, PLUM Sprint 230324)
- Resource "authz:tenant:admin" is deprecated and replaced by several resources (#183, PLUM Sprint 230412)
- Viewing and browsing all tenants requires superuser privileges (#183, PLUM Sprint 230412)
- Seacat Admin built-in resources are not editable (#183, PLUM Sprint 230412)
- Mock mode option of SMSbrana.cz provider changed (#191, PLUM Sprint 230412)

### Fix
- Improve last login search performance (#173, PLUM Sprint 230324)
- M2M session now has access to all the M2M credentials' assigned tenants (#186, PLUM Sprint 230324)
- Fix tenant check in role assignment (#187, PLUM Sprint 230324)
- Fix credential service lookup (#192, PLUM Sprint 230412)
- Fix pymongo import error (#193, PLUM Sprint 230412)
- Fix client initialization in provisioning (#194, PLUM Sprint 230412)

### Features
- Per-client configurable authorization, login and cookies (#156, PLUM Sprint 230324)
- External login ident stored (#185, PLUM Sprint 230324)
- Granular access control for Admin API (#183, PLUM Sprint 230412)
- SMTP provider mock mode (#191, PLUM Sprint 230412)

### Refactoring
- OpenAPI docs updated (#181, PLUM Sprint 230324)
- Bulk-unassign tenants using "UNASSIGN-TENANT" (#189, PLUM Sprint 230324)

---


## v23.13-beta

### Breaking changes
- Renamed the Code Challenge Method client feature (#168, PLUM Sprint 230224)
- Code Challenge Method is now enforced if set (#168, PLUM Sprint 230224)
- Invalid OAuth redirect URIs raise a warning (#157, PLUM Sprint 230310)

### Fix
- Removed required fields from client update (#144, PLUM Sprint 230113)
- Store client cookie domain (#147, PLUM Sprint 230113)
- Efficient count in MongoDB credential provider (#150, PLUM Sprint 230127)
- Fix sync method in Batman module (3c68cb8, PLUM Sprint 230210)
- Fix cookie client session flow (#155, PLUM Sprint 230210)
- Renaming resources without description (#158, PLUM Sprint 230210)
- Batman does not add nonexistent roles to Kibana users (#159, PLUM Sprint 230210)
- Fixed empty string check in client registration (#168, PLUM Sprint 230224)

### Features
- Allow unsetting some client features (#148, PLUM Sprint 230113)
- OAuth 2.0 PKCE challenge (RFC7636) (#152, PLUM Sprint 230127)
- Session tracking ID introduced (#135, PLUM Sprint 230210)
- Clients can register a custom login_uri ~~and login_key~~ (#151, PLUM Sprint 230210)
- Authorize request adds client_id to login URL query (#151, PLUM Sprint 230210)
- Upgrade Docker image OS to Alpine 3.17 (#166, PLUM Sprint 230224)
- ~~Assign roles and tenants to multiple credentials at once (#146, PLUM Sprint 230113)~~
- Allow OAuth authorize requests with anonymous sessions (#165, PLUM Sprint 230224)
- Allow extra login parameters to be supplied in login prologue body (#169, PLUM Sprint 230310)
- Assign roles and tenants to multiple credentials at once (#167, PLUM Sprint 230310)
- Introduce event type descriptors (#172, PLUM Sprint 230310)
- OAuth redirect URI validation options (#157, #175, PLUM Sprint 230310)
- TOTP secrets moved to dedicated collection (#176, PLUM Sprint 230310)


### Refactoring
- Regex validation of cookie_domain client attribute (#144, PLUM Sprint 230113)
- Swagger doc page uses the same auth rules as ASAB API (#164, PLUM Sprint 230224)
- Renamed the Code Challenge Method client feature (#168, PLUM Sprint 230224)
- Code Challenge Method is now enforced if set (#168, PLUM Sprint 230224)

---


## v23.03

### Breaking changes
- Authorize endpoint no longer authorizes unregistered clients (#137, PLUM Sprint 230113)
- Introspecting a cookie-based client session requires client_id in query (#137, PLUM Sprint 230113)

# Fix
- Remove set_cookie from authorize response (#125, PLUM Sprint 221202)
- Attempts to access a nonexistent tenant result in 403 (#133, #138, PLUM Sprint 221216)
- Fixed default registration expiration (#142, PLUM Sprint 230113)

### Features
- Client registration allows custom client ID (#128, PLUM Sprint 221202)
- Login with external OAuth2 (Facebook) (#129, PLUM Sprint 221216)
- Cookie-based client sessions can now authorize for a specific scope and tenant (#137, PLUM Sprint 230113)
- Standardized error codes in authorize response (#137, PLUM Sprint 230113)
- OIDC-standardized scope values (#143, PLUM Sprint 230113)
- M2M sessions are now authorized for all the assigned tenants (#141, PLUM Sprint 230113)

### Refactoring
- Cookie introspection for anonymous access is moved to a separate endpoint (#124, PLUM Sprint 221216)

---


## v22.48

### Breaking changes
- Access to tenants must be requested in authorization scope (#92, PLUM Sprint 221118)

### Features
- Anonymous sessions for unauthenticated user access (#120, PLUM Sprint 221118)
- Display blocked LDAP credentials as suspended (#123, PLUM Sprint 221118)
- Access to tenants must be requested in authorization scope (#92, PLUM Sprint 221118)
- Resource `authz:tenant:access` grants access to any tenant (#92, PLUM Sprint 221118)

### Refactoring
- MySQL and XMongoDB inherit from read-only provider class (#122, PLUM Sprint 221118)
- Userinfo fields `preferred_username` and `phone_number` have been renamed (#92, PLUM Sprint 221118)

---


## v22.46

### Breaking changes
- Endpoint for updating custom tenant data changed (#98, PLUM Sprint 221104)
- Unset credential phone/email by setting it to null instead of empty string (#117, PLUM Sprint 221104)

### Fix
- Logout with ID token (#116, PLUM Sprint 221104)
- Disable registration service when no credential provider supports registration (#118, PLUM Sprint 221104)

### Features
- Roles have an optional "description" field (#103, PLUM Sprint 221021)
- User registration (invitation only) (#86, PLUM Sprint 221021)
- Delete and rename resources (#113, PLUM Sprint 221104)
- List roles that contain a specific resource (#113, PLUM Sprint 221104)
- Include session ID and parent session ID in ID token (#116, PLUM Sprint 221104)

### Refactoring
- Keep superuser role after provisioning (#102, PLUM Sprint 221021)
- Endpoint for updating custom tenant data changed (#98, PLUM Sprint 221104)
- Unset credential phone/email by setting it to null instead of empty string (#117, PLUM Sprint 221104)

---


## v22.44

### Fix
- Removed client values that are not implemented yet (#91, PLUM Sprint 220923)
- Fix client initialization in provisioning (#101, PLUM Sprint 221021)

### Features
- New MongoDB credential provider with configurable queries (#90, PLUM Sprint 220909)
- Client list searches both by _id and client_name (#91, PLUM Sprint 220923)
- Endpoint for ID token validation (#93, PLUM Sprint 220923)
- List tenants and roles for multiple credentials (#94, PLUM Sprint 221007)

### Refactoring
- Simplified Admin UI client provisioning setup (#95, PLUM Sprint 221007)
- Endpoint for updating custom tenant data changed (#98, PLUM Sprint 221007)

---


## v22.38

### Breaking changes
- Userinfo endpoint no longer accepts `tenant` parameter (#69, PLUM Sprint 220909)
- Userinfo `resources` is now an object with tenant keys (#69, PLUM Sprint 220909)

### Fix
- Handle old assignments of nonexisting credentials (#79, PLUM Sprint 220715)
- Check for the existence of tenant when creating a role (#88, PLUM Sprint 220909)

### Features
- OpenID Connect client registration (#77, PLUM Sprint 220729)
- Custom credentials data included in userinfo response (#81, PLUM Sprint 220729)

### Refactoring
- Provisioning config in a dedicated JSON file (#80, PLUM Sprint 220729)
- Userinfo endpoint no longer accepts `tenant` parameter (#69, PLUM Sprint 220909)
- Userinfo `resources` is now an object with tenant keys (#69, PLUM Sprint 220909)

---


## v22.30

### Fix
- Remove email and phone requirement from M2M credential creation (#73, PLUM Sprint 220715)
- Fix basic auth for M2M credentials (#74, PLUM Sprint 220715)
- Fix the format of M2M credential creation policy (#78, PLUM Sprint 220715)
- Fixed two-stage build (1b354f2c, PLUM Sprint 220715)

### Refactoring
- Move password change components into credentials submodule (#75, PLUM Sprint 220715)


---


## v22.28

### Fix
- Fix resource check in Batman ELK (#70, PLUM Sprint 220701)

---


## v22.27

### Breaking changes
- WebAuthn data format changed: Existing WebAuthn credentials are invalidated (#63, PLUM Sprint 220617)
- External login storage changed: Existing external login credentials are invalidated (#60, PLUM Sprint 220701)

### Fix
- Fixed child session filtering (#66, PLUM Sprint 220701)

### Refactoring
- Include relaying party ID in WebAuthn storage (#63, PLUM Sprint 220617)
- Dedicated collection for external login credentials (#60, PLUM Sprint 220701)
- Tenant name proposer is not public (#65, PLUM Sprint 220701)
- Session detail includes parent session ID (71f83c0b, PLUM Sprint 220701)

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
