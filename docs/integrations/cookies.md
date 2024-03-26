---
title: HTTP Cookies
---

# HTTP Cookies 🍪

SeaCat Auth provides cookie-based authentication for applications that do not implement OAuth2.
Different configuration is needed for [single-domain](#single-domain-setting) and 
for [multi-domain](#multi-domain-setting) settings.


## <a name="single-domain-setting"></a> Single-domain setting

If all the applications that you want to protect run on the same domain as your SeaCat Auth service (or its subdomains), 
you only need to configure the **root cookie**.
This cookie is sent to the user automatically after successfully logging in.


### Service configuration

Root cookie is configured in section `[seacatauth:cookie]`.
The available config options are
- `name`: Cookie name, defaults to `SeaCatSCI`
- `domain`: Cookie domain. It has no default and must be explicitly configured.

**`NOTE:`** To fully work in all major browsers, cookie domain must contain at least two dots (requirement by Firefox).
For example, `localhost` or `.xyz` may not work properly, but `.app.localhost` or `.example.xyz` should work fine.


#### Example

```ini
[seacatauth:cookie]
domain=.service.xyz
```

*Such cookie is valid on the `service.xyz` domain and all of its subdomains and subpaths, 
such as `auth.service.xyz` or `myapp.test.service.xyz/example`.*


### Setting up cookie introspection

Cookie introspection is a way of authenticating and authorizing requests to a protected location.
Any user request to such a location is checked for whether it has a valid SeaCat Auth cookie in the header.
When it does, the request continues to the protected location.
When it does not have a valid cookie, a `HTTP 401 Not Authorized` response is sent back to the user. 
Or the user can be directly forwarded to an authorization endpoint.

The cookie introspection endpoint is found at path `/nginx/introspect/cookie` and uses `POST` requests.
Furthermore, it has the capability to add certain information about the user into HTTP X-headers, 
such as username, roles or tenants.
This is done using `add=` query parameters in the introspection call.
*See the SeaCat Auth Postman collection for more details about this endpoint.*

Introspection endpoint configuration:

```nginx
location = /_cookie_introspect {
    internal;
    proxy_method          POST;
    proxy_set_body        "$http_authorization";
    proxy_pass            <SEACAT_AUTH_SERVICE_URL>/nginx/introspect/cookie;
    proxy_ignore_headers  Cache-Control Expires Set-Cookie;
}
```

Example of a cookie-protected location configuration:

```nginx
location / {
    proxy_pass <PROTECTED_LOCATION_URL>;
    
    auth_request        /_cookie_introspect;
    auth_request_set    $authorization $upstream_http_authorization;
    proxy_set_header    Authorization $authorization;
}


```


---

## <a name="multi-domain-setting"></a> Multi-domain setting

If some of your applications run on a different domains than SeaCat Auth service, 
you need to set up an **application cookie** and a **cookie entry endpoint** for each of those domains.
Unlike the *root cookie*, these cookies are not handed out automatically after login.
To obtain them, it is necessary to make a cookie request call.


### Cookie request flow

❓ TODO: Unauthenticated user flowchart ❓

- User tries to access a protected location without required application cookie
- NGINX cookie introspection fails and the user is redirected to OIDC authorize endpoint
- Authorize endpoint redirects the user to login screen
- The user logs in
- The user is redirected to application-cookie request endpoint with an authentication code in the query string
- The cookie request endpoint exchanges the authentication code for a cookie 
  and redirects the user to a pre-configured URL


### Configuration

Each cookie is configured in its own section called `[seacatauth:cookie:<APP_DOMAIN_ID>]`.
The `<DOMAIN_ID>` is used in cookie request URL for its corresponding domain.

```ini
[seacatauth:cookie]
; This is the root cookie, it is required both in single- and multi-domain setting
domain=auth.service.xyz

[seacatauth:cookie:myservice]
domain=my.service.xyz
redirect_uri=http://my.service.xyz/home

[seacatauth:cookie:anotherservice]
domain=service.elsewhere.xyz
redirect_uri=http://service.elsewhere.xyz/discover
```

`redirect_uri` specifies where the user is redirected after successful cookie request.


### Cookie entry endpoint

`GET /cookie/entry/<APP_DOMAIN_ID>`

Exchanges authorization code for application cookie. 
It's necessary to provide `grant_type=authorization_code` and `code=......` query parameters in the request.

E.g.:

`GET http://my.service.xyz/auth/cookie/entry/myservice?grant_type=authorization_code&code=4x0fDvBTuSM3dWlp7t2560A4wtCB199dcbLU5pphe8AagCpM`


### NGINX configuration

Each of the configured domains must have a proxy to the **cookie introspection** and **cookie request** endpoints.
The introspection endpoint is configured exactly the same as in the single-domain case:

```nginx
location = /_cookie_introspect {
    internal;
    proxy_method          POST;
    proxy_set_body        "$http_authorization";
    proxy_pass            <SEACAT_AUTH_PUBLIC_API_INTERNAL_URL>/nginx/introspect/cookie;
    proxy_ignore_headers  Cache-Control Expires Set-Cookie;
}
```

- `<SEACAT_AUTH_PUBLIC_API_INTERNAL_URL>` is the internal base URL of your SeaCat Auth public API.

Locations which use cookie introspection should set their error page to OIDC authorize endpoint 
with `scope=openid&response_type=code` for automatic login prompt.
The redirect URL should point to the **cookie request** endpoint with `grant_type=authorization_code`:

```nginx
server_name <APP_DOMAIN>

...

location /auth/cookie_entry {
	proxy_pass <SEACAT_AUTH_PUBLIC_API_INTERNAL_URL>/cookie/entry/<APP_DOMAIN_ID>;
}
```

- `<APP_DOMAIN>` is your application domain, different from SeaCat Auth domain.
- `<APP_DOMAIN_ID>` is the ID of your application domain, as you configured it in SeaCat Auth service configuration.
- `<SEACAT_AUTH_PUBLIC_API_INTERNAL_URL>` is the internal base URL of your SeaCat Auth public API.

```nginx
location / {
	proxy_pass <PROTECTED_LOCATION_URL>;

	auth_request        /_cookie_introspect;
    auth_request_set    $authorization $upstream_http_authorization;
    proxy_set_header    Authorization $authorization;
    
    error_page 401 403 <SEACAT_AUTH_PUBLIC_API_URL>/openidconnect/authorize?response_type=code&scope=openid&client_id=signin&redirect_uri=<APP_DOMAIN>/auth/cookie_entry?grant_type=authorization_code;
}
```

- `<PROTECTED_LOCATION_URL>` is the internal URL of your protected location.
- `<SEACAT_AUTH_PUBLIC_API_URL>` is the public base URL of your SeaCat Auth public API.
