---
title: Recommended deployment
---

# Recommended deployment

This chapter describes the recommended way of how TeskaLabs SeaCat Auth deployment.


## Architecture overview

<img src=".././teskalabs-seacat-auth-tokens.drawio.svg" alt="TeskaLabs SeaCat Auth: Diagram of the Recommended deployment architecture"/>


## Description

The recommended application gateway for TeskaLabs SeaCat Auth is [NGINX](https://www.nginx.com).
NGINX isolates the public network (Internet) from the internal private network and serves as so-called "interception point" for Authentication.
Multiple NGINX instances can be operated at once.

The browser respective web applications and mobile applications uses _Access tokens_ or _Cookies_ for authentication purposes.

NXING intercepts incoming requests from the public network and in cooperation with TeskaLabs SeaCat Auth, it exchanges the _Access tokens_ / _Cookies_ by _ID tokens_ and other configured authentication information.
_ID Token_ is added by NGINX to the HTTP header of incoming requests.

_ID Token_ is then used internally by microservices and authentication and authorization resource.

