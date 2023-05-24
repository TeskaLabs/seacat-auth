---
title: Quick start
---

# Quick start

This is a quick start guide for _TeskaLabs SeaCat Auth_, it should get you up to speed swiftly.


## Prerequisites

Following list contains all prerequisities for a successful deployment of the _SeaCat Auth_:

* [Docker](https://www.docker.com)
* [docker-compose](https://docs.docker.com/compose/)
* Unrestricted Internet connection

_Note: This guide is designed for Windows (using WSL2 and Docker), Mac OS (using Docker Desktop) and Linux._


## Step 1: Create the deployment directory

We assume in this guide that _SeaCat Auth_ will be deployed into the `/opt/site-auth`.

_Note: We also call the deployment directory a "site"._

The structure of a deployment directory:

```
/opt/site-auth
  seacatauth-conf/
    seacatauth.conf
  mongodb-data/
  nginx-conf/
    nginx.conf
  nginx-root/
    index.html
  seacat-auth-webui/
  seacat-webui/
  log/
  docker-compose.yml
```

The [SeaCat Auth GitHub repository](https://github.com/TeskaLabs/seacat-auth) contains a template of the deployment directory in the `./doc/docker` directory.
This template of the deployment directory can be also downloaded [here](https://nightly.link/TeskaLabs/seacat-auth/workflows/ci/main/seacat-auth-docker-starter.zip).


## Step 2: Adjust SeaCat Auth configuration

  - **[Configure an SMTP server](../config/mail-server).**  
    Setting up a user account in SeaCat Auth requires sending an email with activation link.


## Step 3: Install Web User Interfaces

- Install **SeaCat Auth Web UI** into `./seacat-auth-webui/` from https://asabwebui.z16.web.core.windows.net/seacat-auth/master/seacat-auth-webui.tar.lzma 

- Install **SeaCat Web UI** into `./seacat-webui/` from https://asabwebui.z16.web.core.windows.net/seacat-auth/master/seacat-auth-webui.tar.lzma 


## Step 4: Launch SeaCat Auth

Execute `docker-compose up -d` in the `/opt/site-auth` directory.

Now _SeaCat Auth_ runs in the so-called provisioning mode.
You can use _SeaCat Web UI_ to finish the setup by creating users etc.
For that step, please [proceed to setting up SeaCat Auth in provisioning mode](../config/provisioning).


## Next steps

### Deploying SeaCat Auth with custom hostname and HTTPS

This part of the guide assumes that your server has a proper public domain name.

- **Obtain an SSL certificate** via (eg. using Let's Encrypt and ACME).

- Nginx configuration template for HTTPS is found at [`nginx-conf/nginx-https.conf`](https://github.com/TeskaLabs/seacat-auth/tree/main/doc/docker/nginx-conf/nginx-https.conf).

- Check that your the SSL key and certificate paths in the Nginx config point to where your SSL certificate and key are.

- In [`seacatauth-conf/seacatauth.conf`](https://github.com/TeskaLabs/seacat-auth/tree/main/doc/docker/seacatauth-conf/seacatauth.conf):
  - Change the hostname of `public_api_base_url` and `auth_webui_base_url`.
  - Optionally, you can also set `[seacatauth:cookie] domain` to match your hostname.

- Run the services using `docker-compose up -d` and [proceed to setting up SeaCat Auth in provisioning mode](../config/provisioning).


#### Custom hostname on localhost

To run SeaCat Auth locally with custom hostname, just add the hostname to `/etc/hosts` on your machine, for example

```
127.0.0.1  auth.test.loc
```

Since you can't obtain a trusted SSL certificate via ACME challenge for internal hostnames, 
you need to generate a **self-signed SSL certificate**:

```sh
openssl req -x509 -newkey rsa:4096 -keyout nginx-conf/key.pem -out nginx-conf/cert.pem -days 365 -nodes
```

*Note that **self-signed certificates are not trusted**, and produce warnings on most devices.*
*They should be only used for development purposes in local environments.*
