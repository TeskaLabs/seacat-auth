FROM alpine:3.17 AS stage1
LABEL maintainer="TeskaLabs Ltd (support@teskalabs.com)"

ENV LANG C.UTF-8

RUN set -ex \
  && apk update \
  && apk upgrade

RUN apk add --no-cache \
  python3 \
  py3-pip \
  libstdc++ \
  openssl \
  openldap

# Create build environment so that dependencies like aiohttp can be build
# Run all as a single command in order to reduce image size --virtual buildenv
RUN apk add --no-cache  \
    git \
    python3-dev \
    libffi-dev \
    openssl-dev \
    gcc \
    g++ \
    musl-dev \
    openldap-dev \
    rust \
    cargo \
&& pip3 install --upgrade pip \
&& pip3 install --no-cache-dir \
    aiohttp \
    aiosmtplib \
    bson \
    motor \
    cryptography \
    jwcrypto>=0.9.1 \
    fastjsonschema \
    passlib \
    bcrypt \
    python-ldap \
    aiomysql \
    jinja2 \
    pyotp \
    webauthn \
    pyyaml \
    bson \
    git+https://github.com/TeskaLabs/asab.git@3af2910ec2e76e97ab623159fc86c37af7b7e1e6

RUN mkdir -p /app/seacat-auth
WORKDIR /app/seacat-auth

# Create MANIFEST.json in the working directory
# The manifest script requires git to be installed
COPY ./.git /app/seacat-auth/.git
RUN asab-manifest.py ./MANIFEST.json


FROM alpine:3.17

RUN apk add --no-cache \
  python3 \
  openssl \
  openldap

COPY --from=stage1 /usr/lib/python3.10/site-packages /usr/lib/python3.10/site-packages

COPY ./seacatauth            /app/seacat-auth/seacatauth
COPY ./seacatauth.py         /app/seacat-auth/seacatauth.py
COPY ./CHANGELOG.md          /app/seacat-auth/CHANGELOG.md
COPY --from=stage1 /app/seacat-auth/MANIFEST.json /app/seacat-auth/MANIFEST.json

COPY ./etc/message_templates /app/seacat-auth/etc/message_templates

RUN set -ex \
  && mkdir /conf \
  && touch /conf/seacatauth.conf
  
WORKDIR /app/seacat-auth
CMD ["python3", "seacatauth.py", "-c", "/conf/seacatauth.conf"]
