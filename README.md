# SeaCat Auth

SeaCat Auth is a microservice that provides authentication, authorization, identity management, session management 
and other access control features.
It is designed to be used as an access control app for other microservices.

📖 Documentation is available at [docs.teskalabs.com](https://docs.teskalabs.com/seacat-auth).

SeaCat Auth provides a rich REST API [documented in a Postman collection](./doc/postman.md).


## Installation

SeaCat Auth uses [uv](https://docs.astral.sh/uv/) for dependency management. Requires Python 3.11+.

### Run with uv

1. Install uv (see [uv installation](https://docs.astral.sh/uv/getting-started/installation/)).

2. Clone this repository and enter it:

```bash
git clone https://github.com/TeskaLabs/seacat-auth.git
cd seacat-auth
```

3. Install project dependencies into a local virtual environment:

```bash
uv sync
```

Optional LDAP support (needs system LDAP development headers):

```bash
uv sync --extra ldap
```

4. Start SeaCat Auth with a config file (for example `etc/seacatauth.conf`):

```bash
uv run python seacatauth.py -c etc/seacatauth.conf
```

### Local editable ASAB

By default, ASAB is installed from GitHub. For local ASAB development, use an editable checkout so changes apply without reinstalling.

1. Clone ASAB next to this repository (sibling directories):

```bash
# from the parent directory that contains seacat-auth/
git clone https://github.com/TeskaLabs/asab.git
```

Layout:

```text
├── asab/
└── seacat-auth/
```

2. From the `seacat-auth` directory, point the `asab` dependency at the local path:

```bash
cd seacat-auth
uv add --editable ../asab
```

This updates `pyproject.toml` with a `[tool.uv.sources]` entry similar to:

```toml
[tool.uv.sources]
asab = { path = "../asab", editable = true }
```

3. Sync and run:

```bash
uv sync
uv run python seacatauth.py -c etc/seacatauth.conf
```

Do not commit the local `[tool.uv.sources]` override. Before committing, restore the git source (for example `git checkout -- pyproject.toml uv.lock`) so CI and Docker keep installing ASAB from GitHub.


## Features

* Authentication
  * Second-factor Authentication (2FA) / [Multi-factor Authentication](https://en.wikipedia.org/wiki/Multi-factor_authentication) (MFA)
  * Supported factors:
    * Password
    * [FIDO2](https://en.wikipedia.org/wiki/FIDO2_Project) / [Webauthn](https://en.wikipedia.org/wiki/WebAuthn)
    * [Time-based One-Time Password](https://en.wikipedia.org/wiki/Time-based_One-Time_Password) (TOTP)
    * SMS code
    * Subnet (ROADMAP)
    * Request header (X-Header)
  * Machine-to-Machine
    * API keys (ROADMAP)
&nbsp;
* Authorization
  * Roles
  * [Role-based access control](https://en.wikipedia.org/wiki/Role-based_access_control) (RBAC)
  * Policies (ROADMAP)
  * [Attribute-based access control](https://en.wikipedia.org/wiki/Attribute-based_access_control) (ABAC) (ROADMAP)
&nbsp;
* Identity management
    * Federation of identities
    * Supported providers:
        * File ([htpasswd](https://httpd.apache.org/docs/2.4/programs/htpasswd.html))
        * In-memory dictionary
        * [MongoDB](https://www.mongodb.com)
        * [ElasticSearch](https://www.elastic.co)
        * [LDAP](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol) and [Active Directory](https://en.wikipedia.org/wiki/Active_Directory)
        * [Google](https://google.com/)
        * Custom provider
&nbsp;
* [Multitenancy](https://en.wikipedia.org/wiki/Multitenancy) including tenant management for other services and applications
* Session management
* [Single-sign on](https://en.wikipedia.org/wiki/Single_sign-on)
* [OpenId Connect](https://openid.net/connect/) / [OAuth2](https://oauth.net/2/)
* [Proof Key for Code Exchange](https://datatracker.ietf.org/doc/html/rfc7636) aka PKCE for OAuth 2.0 public clients
* Authorization/authentication introspection backend for [NGINX](https://nginx.org)
* Authorization/authentication interceptor for 3rd party applications (aka Batman)
  * Kibana &amp; ElasticSearch
  * [Grafana](https://grafana.com)
  * Docker registry / NGINX (ROADMAP)
  * HTTP [Basic Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication)
* Audit trail
* Provisioning mode
* Structured logging (Syslog) and telemetry


## Design

 * Authentication Service
 * Authorization Service
 * API Service
 * Tenant Service
 * Credentials Service
 * Session Service
 * Notification Service
 * Audit Service
 * OpenIDConnect Service
 * Provisioning Service
 * Batman Service
 * Cookie Service


### Components

This section clarifies role of various components in the SeaCat Auth ecosystem.

#### Web User Interfaces

There are two separate Web UIs (user interfaces):

* SeaCat WebUI provides a graphical interface for Seacat Auth administration.
* [SeaCat Auth WebUI](https://github.com/TeskaLabs/seacat-auth-webui) provides a login form, a password reset screen, and self-care user portal.

#### Docker and Docker Compose

The whole site installation can be dockerized and deployed using docker-compose, 
see [the documentation](https://docs.teskalabs.com/seacat-auth/getting-started/quick-start).

[Docker image is available from DockerHub](https://hub.docker.com/r/teskalabs/seacat-auth)

#### Nginx

Nginx is used to forward requests coming from outside of the environment to protected locations.
These requests are first forwarded to SeaCat Auth, where their authentication state is evaluated.
If already authenticated, the request is allowed into the protected space.

#### MongoDB

Is employed by SeaCat Auth for storage of known users and other related persistent data.



## Unit test

```bash
uv sync --only-group test
uv run --no-sync python -m unittest test
```
