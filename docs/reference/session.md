---
title: Session
---

# Session

- Session object represents user or machine authentication and authorization.
- The two basic session types are *root* and *client*. 
  Client sessions can be either *access-token-based* or *cookie-based*. 
  Furthermore, there are special session types: *machine-to-machine* and *anonymous* session.

## Root session

- Root session is created at user login. 
- Used as a proof of user authentication (Single Sign-On) for OAuth authorization requests.
- Uniquely identified by a browser cookie (called `SeaCatSCI` by default).

## Client session (subsession)

- Used as a proof of user and client authorization.
- Created as a result of a successful OAuth authorization request at `/openidconnect/authorize` endpoint.
- Descends from a root session; user root session is a prerequisite to creating a client session for that user.
- Uniquely identified either by OAuth 2.0 Access Token or by browser cookie.

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
