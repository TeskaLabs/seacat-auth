---
title: Components
---

# Components of SeaCat Auth

This section clarifies the roles of various components in the SeaCat Auth ecosystem.

### Web User Interfaces

There are two separate Web UIs (user interfaces):

* [SeaCat WebUI](http://gitlab.teskalabs.int/seacat/seacat-webui) provides a graphical interface for SeaCat Auth administration.
* [SeaCat Auth WebUI](http://gitlab.teskalabs.int/seacat/seacat-auth-webui) provides a login form, a password reset screen, and other common-user-facing screens.

### Docker and Docker Compose

The whole site installation can be dockerized and deployed using docker-compose, see the [quick start quide](../getting-started/quick-start).

### Nginx

Nginx is used to forward requests coming from outside of the environment to protected locations.
These requests are first forwarded to SeaCat Auth, where their authentication state is evaluated.
If already authenticated, the request is allowed into the protected space.

### MongoDB

Is employed by SeaCat Auth for storage of known users and other related persistent data.