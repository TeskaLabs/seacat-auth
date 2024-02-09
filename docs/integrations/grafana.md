---
title: Grafana
---

# Using Seacat authorization in Grafana

Grafana has native support for OAuth authorization flow, so connecting it to Seacat Auth is quite straightforward. 

- In Seacat Admin UI, register a new client for grafana. Note down the client ID.
- Configure generic OAuth in the Grafana section in your `docker-compose.yaml` file through environment variables

```yaml
services:
  grafana:
    user: "0"
    restart: on-failure:3
    image: grafana/grafana:10.3.1
    network_mode: host
    volumes:
      - ./grafana/data:/var/lib/grafana
    environment:
      GF_SERVER_ROOT_URL: ${PUBLIC_URL}/grafana/
      GF_AUTH_SIGNOUT_REDIRECT_URL: ${PUBLIC_URL}
      GF_AUTH_GENERIC_OAUTH_ENABLED: true
      GF_AUTH_GENERIC_OAUTH_TLS_SKIP_VERIFY_INSECURE: true
      GF_AUTH_GENERIC_OAUTH_AUTO_LOGIN: true
      GF_AUTH_GENERIC_OAUTH_USE_PKCE: false
      GF_AUTH_GENERIC_OAUTH_USE_REFRESH_TOKEN: false
      GF_AUTH_GENERIC_OAUTH_NAME: Seacat Auth
      GF_AUTH_GENERIC_OAUTH_CLIENT_ID: ${GRAFANA_CLIENT_ID}
      GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET: ""
      GF_AUTH_GENERIC_OAUTH_SCOPES: openid email profile
      GF_AUTH_GENERIC_OAUTH_AUTH_URL: ${PUBLIC_URL}/api/openidconnect/authorize
      GF_AUTH_GENERIC_OAUTH_TOKEN_URL: http://${PUBLIC_SEACAT_AUTH_NETLOC}/openidconnect/token
      GF_AUTH_GENERIC_OAUTH_API_URL: http://${PUBLIC_SEACAT_AUTH_NETLOC}/openidconnect/userinfo
      GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_STRICT: true
      GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH: contains(resources."*"[*], 'authz:superuser') && 'Admin' || contains(resources."*"[*], 'grafana:edit') && 'Editor' || contains(resources."*"[*], 'grafana:access') && 'Viewer'
```
