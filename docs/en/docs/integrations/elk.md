---
title: Elasticsearch and Kibana
---

# Connecting to Elasticsearch and Kibana

This is a guide to configuring SeaCat Auth as a proxy to [Kibana](https://www.elastic.co/kibana/) users and roles.
As Kibana is not OAuth-compatible and supports only Basic Authentication, 
integrating it into a Single Sign-On environment requires a special approach.
The **SeaCat Auth Batman** component (Basic Auth Token MANager) is designed exactly for this task -
it "translates" Seacat session cookies into Basic Auth headers and
synchronizes Kibana/Elasticsearch users with Seacat Auth credentials and their access rights.


## How does it work?

The flow for using Batman auth is almost the same as the [cookie auth flow](index#cookie-authorization-flow), 
the only difference being in the type of introspection used. 
Instead of the `PUT /nginx/introspect/cookie` endpoint (which exchanges Seacat client cookie for ID token), 
Batman auth uses `PUT /nginx/introspect/batman` (which exchanges Seacat client cookie for Basic auth header).


## Configuration example

Let's set up Seacat Batman authorization for our Kibana app. We need to have 
[Elasticsearch](https://www.elastic.co/elasticsearch/) and [Kibana](https://www.elastic.co/kibana/) applications 
up and running, as well as [a working instance of Seacat Auth with Nginx reverse proxy](../getting-started/quick-start). 
We will need to configure these three components:

- Update **Seacat Auth configuration** with `[batman:elk]` section to allow it to use Elasticsearch API to synchronize 
  users and manage their authorization.
- Create and configure a **Kibana client**. This client object represents and identifies Kibana 
  in communication with Seacat Auth.
- Prepare the necessary **server locations** in Nginx config.

### Seacat Auth configuration

Create the ELK Batman section and provide Elasticsearch base URL and API credentials, e.g.

```ini
[batman:elk]
url=http://localhost:9200
username=admin
password=elasticpassword
```

### Client configuration

Use Seacat Auth client API (or Seacat Admin UI) to register Kibana as a client. 
The request body must include a human-readable `client_name`, `redirect_uris` array containing the URL of Kibana web UI 
and `cookie_entry_uri` for your hostname (we define this location in the Nginx configuration below.).
We also recommend to set `redirect_uri_validation_method` to `prefix_match` if you want to allow immediate redirections 
to Kibana subpaths.
In our case, we can send the following request (Remember to use your actual hostnames instead of `example.com`!):

```
POST /client
{
	"client_name": "Kibana",
	"redirect_uri_validation_method": "prefix_match",
	"redirect_uris": [
		"https://example.com/kibana"
	],
	"cookie_entry_uri": "https://example.com/seacat_auth/cookie"
}
```

The server will respond with our client's assigned ID and other attributes:

```
{
	"client_id": "RZhlE-D4yuJxoKitYVL4dg",
	"client_id_issued_at": 1687170414,
	"application_type": "web",
	...,
	"cookie_name": "SeaCatSCI_QLFLEAU4D726UPA3"
}
```

We will use the `client_id` and `client_cookie` in the next step.

### Nginx configuration

The minimal configuration requires the following three locations to be defined in nginx:

- **Client site location:** Protected public location with Kibana web app.
- **Client introspection:** Internal endpoint used by the nginx `auth_request` directive.
- **Client cookie entry point:** Public endpoint which dispenses the Seacat client cookie at the end of a successful 
  authorization flow.

#### Client site location

```nginx
location /kibana/ {
	# Kibana upstream
	proxy_pass http://kibana_api;

	# Auth introspection endpoint
	auth_request /_kibana_introspection;

	# Pass the Batman header obtained from Seacat Auth introspection to Kibana
	auth_request_set $auth_header $upstream_http_authorization;
	proxy_set_header Authorization $auth_header;

	# In the case when introspection detects invalid authorization, redirect to OAuth authorize endpoint
	# !! Use your client's actual client_id and your site's actual hostname !!
	error_page 401 https://example.com/auth/api/openidconnect/authorize?response_type=code&scope=cookie%20batman&client_id=RZhlE-D4yuJxoKitYVL4dg&redirect_uri=https://example.com$request_uri;

	# Headers required by Kibana
	proxy_http_version 1.1;
	proxy_set_header Upgrade $http_upgrade;
	proxy_set_header Connection 'upgrade';
	proxy_set_header Host $host;
	proxy_cache_bypass $http_upgrade;
}
```

#### Client introspection

```nginx
location = /_kibana_introspection {
	internal;

	# Seacat Auth Batman introspection upstream
	# !! Use your client's actual client_id !!
	proxy_method          POST;
	proxy_pass            http://seacat_auth_api/nginx/introspect/batman?client_id=RZhlE-D4yuJxoKitYVL4dg;

	proxy_set_header      X-Request-URI "$request_uri";
	proxy_ignore_headers  Cache-Control Expires Set-Cookie;

	# Introspection response caching
	proxy_buffer_size     128k;
	proxy_buffers         4 256k;
	proxy_busy_buffers_size  256k;
	proxy_cache           kibana_auth;
	# !! Fill in your client's actual cookie_name !!
	proxy_cache_key       $cookie_SeaCatSCI_QLFLEAU4D726UPA3;
	proxy_cache_lock      on;
	proxy_cache_valid     200 10s;
}
```

#### Cookie entry point

Must be located on the same hostname as the protected client location. 
There should be one cookie entry point exposed per hostname, shared by all cookie-based clients on that hostname.

```nginx
location = /seacat_auth/cookie {
	# Seacat Auth cookie entry upstream
	proxy_method          POST;
	proxy_pass            http://seacat_auth_api/cookie/entry;

	# Transfer the OAuth authorization code from query to request body
	# !! Use your client's actual client_id !!
	proxy_set_header      Content-Type "application/x-www-form-urlencoded";
	proxy_set_body        $args;
}
```