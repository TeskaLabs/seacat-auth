# Using Seacat Auth with Postman

Postman is a useful development tool for debugging apps that interact with Seacat Auth.
The major advantage is that Postman natively **handles OAuth2.0 authentication** and provides tools for **auth token management**.

## Prerequisites

- Running instance of SeaCat Auth
  - Check the `[general]` section in the config to make sure `auth_webui_base_url` and 
    `public_api_base_url` variables point to the actual URLs of your SeaCat Auth WebUI 
- Running instance of SeaCat Auth WebUI
  - Auth WebUI is required for authenticating in Seacat Auth
  - Check the proxy routing (in Nginx) to make sure it points 
    to you SeaCat Auth backend correctly

## Configure your Postman environment

- [Import the latest collection](https://learning.postman.com/docs/getting-started/importing-and-exporting-data/) 
  from the SeaCat Auth repo (located at `doc/seacat-auth-api.postman_collection.json`)
- Set up a SeaCat Auth [Postman environment](https://learning.postman.com/docs/sending-requests/managing-environments/). 
  The following variables need to be defined:
  - `BASE_URL` should contain the base URL of your Seacat API, for example `https://my-domain.int/seacat/api/seacat_auth` 
  - `AUTH_URL` should contain the base URL of your Seacat Auth, for example `https://my-domain.int/auth`. 
    It is used for authenticating your session.

## Create an OAuth2 authorized session

- In the **Collections** panel, open the context menu of your SeaCat Auth collection and choose **Edit**. 
- Navigate to **Authorization** tab.
- For **Authorization type** choose **OAuth 2.0**
- [Request a new access token](https://learning.postman.com/docs/sending-requests/authorization/#requesting-an-oauth-20-token) 
  and log in to your SeaCat Auth WebUI
- Your Postman session is now authenticated!

### Postman access token details

 * Grant type: "Authorization Code"
 * Callback URL: http://localhost:8080/???? (???)
 * Auth URL: http://localhost:8080/openidconnect/authorize
 * Access Token URL: http://localhost:8080/openidconnect/token
 * Client Id: [any string]
 * Client Secret: [any string]
 * Scope: `openid`
 * State: [empty string]
 * Client Authentication: Send client credentials in the body


**`NOTE`** Some API requests will be fulfilled only if you have access to specific admin resources 
(`authz:superuser` or `authz:tenant:admin`). 
Check the description of those calls to see if there is any access restriction.
