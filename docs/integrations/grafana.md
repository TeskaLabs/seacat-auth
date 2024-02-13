---
title: Grafana
---

# Using Seacat authorization in Grafana

This guide will show you how to set up [Grafana](https://grafana.com/) to use Seacat Auth login and access control.
Grafana has native support for OAuth authorization flow, so connecting it to Seacat Auth is quite straightforward. 

- Register a new client for your Grafana application in the Clients section of Seacat Admin UI. Note down the client ID.
- Create the following resource IDs in the Resources section of Seacat Admin UI (or choose different names, but remember to change them in Grafana `role_attribute_path` configuration below):
  - `grafana:access` - will be mapped to [Grafana's _Viewer_ role](https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/#organization-roles), 
    which allows the user to browse dashboards and other data, but not to create or change anything.
  - `grafana:edit` - will be mapped to [Grafana's _Editor_ role](https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/#organization-roles), 
    which allows the user to browse and edit dashboards and other data.
- Configure Grafana to use your Seacat Auth instance as a [Generic OAuth provider](https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/generic-oauth/).
  This can be either done in Grafana config file, or perhaps more conveniently using environment variables in your `docker-compose.yaml` file as following:

```yaml
services:
  grafana:
    image: grafana/grafana:10.3.1
    network_mode: host
    (...)
    environment:
      ## Required configuration options
      # URL where Grafana is accessible in the browser
      GF_SERVER_ROOT_URL: ${PUBLIC_URL}/grafana/
      # Enable OAuth login
      GF_AUTH_GENERIC_OAUTH_ENABLED: true
      # Client ID issued by Seacat Auth
      GF_AUTH_GENERIC_OAUTH_CLIENT_ID: ${GRAFANA_CLIENT_ID}
      # Client secret issued by Seacat Auth (not supported yet)
      GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET: ""
      # OAuth scopes that Grafana will request from Seacat Auth
      GF_AUTH_GENERIC_OAUTH_SCOPES: openid email profile
      # Public URL of Seacat Auth OAuth Authorization endpoint
      GF_AUTH_GENERIC_OAUTH_AUTH_URL: ${PUBLIC_URL}/api/openidconnect/authorize
      # Internal URL of Seacat Auth OAuth Token endpoint
      GF_AUTH_GENERIC_OAUTH_TOKEN_URL: ${INTERNAL_SEACAT_AUTH_URL}/openidconnect/token
      # Internal URL of Seacat Auth OAuth Userinfo endpoint
      GF_AUTH_GENERIC_OAUTH_API_URL: ${INTERNAL_SEACAT_AUTH_URL}/openidconnect/userinfo
      
      ## Additional useful configuration options
      # Where the user is redirected after pressing the "Sign out" button
      GF_AUTH_SIGNOUT_REDIRECT_URL: ${PUBLIC_URL}
      # Skip Grafana login screen and sign the user in automatically
      GF_AUTH_GENERIC_OAUTH_AUTO_LOGIN: true
      # Disable PKCE
      GF_AUTH_GENERIC_OAUTH_USE_PKCE: false
      # Disable refresh tokens (not supported yet)
      GF_AUTH_GENERIC_OAUTH_USE_REFRESH_TOKEN: false
      # OAuth provider name displayed on the "Sign in with ..." button on the Grafana login screen
      GF_AUTH_GENERIC_OAUTH_NAME: Seacat Auth
      # Get the user login name and screen name primarily from OpenID Connect standard field "preferred_username", with fallback to "username" and "sub" fields
      GF_AUTH_GENERIC_OAUTH_LOGIN_ATTRIBUTE_PATH: preferred_username || username || sub
      GF_AUTH_GENERIC_OAUTH_NAME_ATTRIBUTE_PATH: preferred_username || username || sub
      # Control user permissions using Seacat Auth authorized resources:
      #   The following JMESPath expression assigns the user a Grafana role depending on the authorized resources in their ID token or Userinfo
      GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH: >
        contains(resources."*"[*], 'authz:superuser') && 'Admin' 
        || contains(resources."*"[*], 'grafana:edit') && 'Editor' 
        || contains(resources."*"[*], 'grafana:access') && 'Viewer'
      # Deny login if the user is not authorized for any of the resources in the expression above
      GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_STRICT: true
```

- `PUBLIC_URL` is the base URL from which Seacat Auth is accessed from the browser, for example `https://example.com`.
- `INTERNAL_SEACAT_AUTH_URL` is the internal URL of Seacat Auth's private web container, typically `http://localhost:8900`.
- `GRAFANA_CLIENT_ID` is the client ID issued by Seacat Auth.

**NOTE:** The above configuration assumes that Grafana backend communicates with Seacat Auth server via secure internal network (usually a VPN). 
If this is not the case and the two services have no shared internal network, configure `GF_AUTH_GENERIC_OAUTH_TOKEN_URL` and `GF_AUTH_GENERIC_OAUTH_API_URL` using public URLs.

If this is your testing environment and you are using a self-signed SSL certificate, you will need to add the following switch as well:
```yaml
GF_AUTH_GENERIC_OAUTH_TLS_SKIP_VERIFY_INSECURE: true
```

For more details about Grafana OAuth configuration, [refer to its documentation](https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/generic-oauth/).
