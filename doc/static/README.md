# How to use SeaCat Auth with Nginx using static files only


## Nginx configuration

The presented configuration consist of following parts:

 * Cookie-based protection, suitable for endpoints that cannot use OAuth2.0
 * OAuth2.0 / OpenID Connect protection
 * Exposure of the OAuth2.0 / OpenID Connect public API of the SeaCat Auth
 * 401 and 403 pages that forwards to a login screen

```
server {
	...


	# This location is protected by the server-side cookie (set by scope=cookie)
	location /cookie_protected {
		auth_request /_cookie_introspect;
		...
	}

	# This *internal* endpoint checks a validity of the cookie and return 200/401/403
	location = /_cookie_introspect {
		internal;
		proxy_method          POST;
		proxy_set_body        "$http_authorization";
		proxy_pass            http://seacat-auth/cookie/nginx;
	}



	# This location is protected by OAuth2.0
	location /oauth2_protected {
		auth_request /_oauth2_introspect;
		
		...
	}

	# This *internal* endpoint check a validity of the access token provided in `Authentication: Bearer <access_token>` header
	location = /_oauth2_introspect {
		internal;
		proxy_method          POST;
		proxy_set_body        "$http_authorization";
		proxy_pass            http://seacat-auth-svc:8081/openidconnect/introspect/nginx;

		proxy_cache           token_responses;     # Enable caching
		proxy_cache_key       $http_authorization; # Cache for each access token
		proxy_cache_lock      on;                  # Duplicate tokens must wait
		proxy_cache_valid     200 10s;             # How long to use each response
		proxy_ignore_headers  Cache-Control Expires Set-Cookie;
	}



	# Expose a public OAuth2.0 / OpenID Connect API of the SeaCat 
	location /openidconnect {
		proxy_pass http://seacat-auth;
	}

	# Kickstart is a 
	location = /kickstart.html {
		root = .../kickstart.html;
	}

	# 401 and 403 forwards to a login page provided by a SeaCat Auth
	error_page 401 /openidconnect/authorize?response_type=code&scope=openid%20cookie&client_id=signin&redirect_uri=/kickstart.html;
	error_page 403 /openidconnect/authorize?response_type=code&scope=openid%20cookie&client_id=signin&redirect_uri=/kickstart.html;
}

```

## Kickstart

See `kickstart.html`, this is a small Javascript app, that get `authorization_code` from OpenID Connect server response and exchange that for the `access_code`.
The access code is stored in the session storage.

