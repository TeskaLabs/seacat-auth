# ---- Build stage ----
FROM alpine:3.21 AS builder
LABEL maintainer="TeskaLabs Ltd (support@teskalabs.com)"

ENV LANG=C.UTF-8

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
&& python3 -m venv /venv \
&& /venv/bin/pip3 install --upgrade pip \
&& /venv/bin/pip3 install --no-cache-dir \
    aiohttp \
    aiosmtplib \
    motor \
    cryptography \
    jwcrypto>=0.9.1 \
    fastjsonschema \
    bcrypt \
    argon2_cffi \
    python-ldap \
    aiomysql \
    jinja2 \
    pyotp \
    webauthn==1.9.0 \
    pyyaml \
    pymongo \
    sentry-sdk \
    "asab[encryption] @ git+https://github.com/TeskaLabs/asab.git"
# There is a broken pydantic dependency in webauthn.
# Remove the version lock once this is fixed.

RUN cat /venv/lib/python3.12/site-packages/asab/__version__.py

RUN mkdir -p /app/seacat-auth
WORKDIR /app/seacat-auth

# Create MANIFEST.json in the working directory
# The manifest script requires git to be installed
COPY ./.git /app/seacat-auth/.git
RUN /venv/bin/asab-manifest.py ./MANIFEST.json


# ---- Runtime stage ----
FROM alpine:3.21

RUN apk add --no-cache \
  python3 \
  openssl \
  openldap

COPY --from=builder /venv /venv
ENV PATH="/venv/bin:$PATH"

COPY ./seacatauth            /app/seacat-auth/seacatauth
COPY ./seacatauth.py         /app/seacat-auth/seacatauth.py
COPY ./CHANGELOG.md          /app/seacat-auth/CHANGELOG.md
COPY --from=builder /app/seacat-auth/MANIFEST.json /app/seacat-auth/MANIFEST.json

COPY ./etc/message_templates /app/seacat-auth/etc/message_templates

RUN set -ex \
  && mkdir /conf \
  && touch /conf/seacatauth.conf
  
WORKDIR /app/seacat-auth
CMD ["python3", "seacatauth.py", "-c", "/conf/seacatauth.conf"]
