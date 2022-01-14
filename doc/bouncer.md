# SeaCat Auth Bouncer

Bouncing mechanism makes sure, that after the user successfully logs in
via SeaCat Auth OpenIDConnect, they are redirected to the specified URL,
even though the URL contains special characters such as hash (#),
which would normally prevent server from redirection to the proper resource.

## BatMan

As default, SeaCat Auth Bouncer redirects user after login to BatMan,
so that the logging in is saved to the cookie there as well.
Without this redirection, the application server such as NGINX
would redirect user back to BatMan and lose parts of the URL (such as #).

## Generic Bouncer configuration

```
[bouncer]
allowed_urls=<MY_URL>/kibana;<MY_URL>/grafana
seacat_auth_url_prefix=/api/seacat
```

`allowed_urls` servers as white list of URLs separated by `;` the user can be redirected to,
other URLs are not allowed to be used in the bouncer and user will get
HTTP 400 - Bad Request response

`seacat_auth_url_prefix` specifies the relative path in the URL the SeaCat Auth runs on,
this is needed for proper redirection to login, BatMan, back to bouncer after login etc.

## Generic BatMan configuration

```
[batman]
oidc_url=<MY_SEACAT_AUTH_URL>/openidconnect
```

`oidc_url` specifies OpenIDConnect URL BatMan redirects user to be logged in
