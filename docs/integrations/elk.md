---
layout: default
title: TeskaLabs SeaCat Auth Documentation
---

# ElasticSearch + Kibana and TeskaLabs SeaCat Auth Batman

This is a guide to configuring SeaCat Auth as a proxy to [Kibana](https://www.elastic.co/kibana/) users and roles.

* This will become a table of contents (this text will be scrapped).
{:toc}

---


## Prerequisites

- [Installation of SeaCat Auth with a reverse proxy and both web UIs.](../getting-started/quick-start)
- [ElasticSearch](https://www.elastic.co/elasticsearch/)
- [Kibana](https://www.elastic.co/kibana/)


## Configuration

Update SeaCat configuration with `[batman:elk]` section containing your ElasticSearch API base URL and admin credentials:

```ini
[batman:elk]
url=<ELASTICSERCH_API_BASE_URL>
username=<ELASTICSERCH_ADMIN_USERNAME>
password=<ELASTICSERCH_ADMIN_PASSWORD>
```

In your Nginx server configuration, create an internal reverse proxy location for `/batman/nginx` endpoint 
in SeaCat Auth public API. 
The following example assumes a SeaCat Auth public container running at `http://localhost:8081`.

```nginx
location = /_batman_introspect {
	internal;
	proxy_method          PUT;
	proxy_set_body        "";
	proxy_set_header      X-Request-URI "$request_uri";
	proxy_pass            http://localhost:8081/batman/nginx;
	proxy_cache_key       $cookie_BatMan;
	proxy_cache_lock      on;
	proxy_cache_valid     200 10s;
	proxy_ignore_headers  Cache-Control Expires Set-Cookie;
}
```

Create a reverse proxy for Kibana.

```nginx
location /kibana/ {
	proxy_pass http://localhost:5601/;
	
	auth_request /_batman_introspect;
	auth_request_set $batman $upstream_http_authorization;
	proxy_set_header Authorization $batman;

	proxy_http_version 1.1;
	proxy_set_header Upgrade $http_upgrade;
	proxy_set_header Connection 'upgrade';
	proxy_set_header Host $host;
	proxy_cache_bypass $http_upgrade;

	error_page 401 <BASE_OIDC_API_PATH>/authorize?response_type=code&scope=openid&client_id=signin&redirect_uri=<BASE_SEACAT_AUTH_API_PATH>/batman&state=$request_uri;
}
```

- `<BASE_OIDC_API_PATH>` is the public (accessible from the user browser) base path to the OpenIDConnect API.
- `<BASE_SEACAT_AUTH_API_PATH>` is the public (accessible from the user browser) base path to SeaCat Auth public API.


## Managing user access

SeaCat Auth Batman automatically scans the roles in your ElasticSearch/Kibana and creates a SeaCat resource for each of them.
For example a role that is called `kibana_admin` becomes available as a resource called `elk:kibana_admin`.
Assigning this resource to a user results in assigning the corresponding Kibana role to them.

- First ensure that your desired Kibana role exists in the list of SeaCat Resources.
- Create a new global SeaCat role or pick an existing one.
- Assign the `elk:...` resource to your SeaCat role.
- Assign the SeaCat role to the chosen user/credential.
- Let the user log out and in again. 

The user should now be able to access Kibana with the newly assigned role.
