---
title: Session
---

# Session

- Session object represents user or machine authentication and authorization.
- The two basic session types are *root* and *client*. 
  Client sessions can be either *access-token-based* or *cookie-based*. 
  Furthermore, there are special session types: *machine-to-machine* and *anonymous* session.

## Single Sign-On session (aka "root session")

- Created at user login. 
- Used as a proof of user authentication (Single Sign-On) for OAuth authorization requests.
- Uniquely identified by a browser cookie (called `SeaCatSCI` by default).

## Client session (subsession)

- Used as a proof of user and client authorization.
- Created as a result of a successful OAuth authorization request at `/openidconnect/authorize` endpoint.
- Descends from a root session; user root session is a prerequisite to creating a client session for that user.
- Uniquely identified either by OAuth 2.0 tokens or by HTTP cookie.

### Access-token-based client session

- Created by authorization request at `/openidconnect/authorize` with `openid` in scope.
- Suitable for clients that support the OAuth 2.0 protocol.
- Uniquely identified by OAuth 2.0 Access Token.

### Cookie-based client session

- Created by authorization request at `/openidconnect/authorize` with `cookie` in scope.
- Suitable for clients that do not support the OAuth 2.0 protocol.
- Uniquely identified by browser cookie.

## Machine-to-machine (M2M) session

- Special type of root session that includes client authentication and authorization.
- Serves as a proof of authentication and authorization in machine-to-machine communication (no human user is involved).

## Anonymous session

- Special type of session that identifies an unauthenticated user.
- Used for tracking visitors at client locations that can be accessed without authentication.
- It is a client session that can exists without a root session. Anonymous root session is created only when
  multiple anonymous client sessions need to be linked together.

## Session lifecycle

- When an end-user successfully signs in, a Single Sign-On (root) session is created. 
  It contains a user identifier and details of the user authentication process: when the authentication happened, 
  what means of authentication were used etc. It is usually long-lived (several days to months).
  The user agent receives an HTTP cookie which identifies this SSO session.
- When the user wants to access a client application, the application asks the Seacat Auth server for authorization 
  to access the end-user data and other resources, which is usually done using the OAuth 2.0 authorization code flow. 
  The first step of the flow is the authorization request, which, if successful, produces a short-lived (not longer 
  than a few minutes) client session and an authorization code which serves as the session identifier. 
  The session contains a reference to the end user's Single Sign-On session and details of the authorization, 
  such as the client application identifier (client ID) and the requested authorization scope.
- The client application then uses the authorization code to make a token request. 
  If successful, this consumes the authorization code and produces a set of longer-lived tokens - an access token 
  and an ID token, which are valid for a few hours, and a refresh token, which is valid for several days to weeks.
  The client session is extended to last as long as the refresh token and updated so that it contains up-to-date user
  info and their authorized tenant and resources.
- The client application then continuously uses the access token as a proof of authorization to resource-owner 
  applications. For example, a frontend Web UI application (client) sends the access token with every REST API request 
  to the backend application (resource owner). The resource owner can ask the authorization server to verify 
  the access token in a so-called _introspection request_.
- When the access token expires, the client application can request a new one using the refresh token. 
  This request results in a new set of tokens (access, refresh and ID) being issued and the client session being 
  once again extended to match the new refresh token.
- When the client session expires or when the client requests to terminate it, the session is deleted together with 
  all its active tokens.
- When the Single Sign-On session expires or when the end-user signs out, the session is invalidated and deleted 
  together with its cookie, with all the client sessions that have been opened under this Single Sign-On session 
  and their tokens.
