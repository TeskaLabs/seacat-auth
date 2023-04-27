---
layout: default
title: TeskaLabs SeaCat Auth Documentation
---

# OAuth2 introspection

* This will become a table of contents (this text will be scrapped).
{:toc}

---

## Set up OAuth2 introspection for a web application

First, register your web application in the Client section of SeaCat UI.
You will obtain `client_id` necessary for the introspection request.

Set up a location for your application in the Nginx configuration:

```nginx
location <APPLICATION_PATH> {
    proxy_pass <INTERNAL_APPLICATION_URL>;
    
    auth_request        /_oauth2_introspect;
    auth_request_set    $authorization $upstream_http_authorization;
    proxy_set_header    Authorization $authorization;

    error_page 401 /auth/api/openidconnect/authorize?<CLIENT_PARAMETERS>&redirect_uri=$request_uri;
}

```

- `<APPLICATION_PATH>` is the path where your application will be accessible to users.
- `<INTERNAL_APPLICATION_URL>` is the internal URL of your application server.
- `<CLIENT_PARAMETERS>` is a query string of your registered client parameters, usually including `client_id`, `response_type`, `scope`. Note that more parameters, such as `client_secret`, may be required depending on the type and configuration of your client. 
Example path with minimal parameters: `/auth/api/openidconnect/authorize?client_id=abc1230ZM3n37BmbtKrqqw&response_type=code&scope=openid&redirect_uri=$request_uri`
