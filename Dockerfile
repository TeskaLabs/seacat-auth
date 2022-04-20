FROM alpine:3.13
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
# Run all as a single command in order to reduce image size
RUN apk add --no-cache --virtual buildenv \
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
    motor \
    cryptography \
    jwcrypto>=0.9.1 \
    fastjsonschema \
    passlib \
    bcrypt \
    python-ldap \
    jinja2 \
    pyotp \
    webauthn \
    git+https://github.com/TeskaLabs/asab.git \
&& apk del buildenv

RUN mkdir -p /app/seacat-auth
WORKDIR /app/seacat-auth

# Create MANIFEST.json in the working directory
# The manifest script requires git to be installed
COPY ./.git /app/seacat-auth/.git
RUN apk add --no-cache --virtual buildenv git \
&& asab-manifest.py ./MANIFEST.json \
&& apk del buildenv
RUN rm -rf /app/seacat-auth/.git

COPY ./seacatauth            /app/seacat-auth/seacatauth
COPY ./seacatauth.py         /app/seacat-auth/seacatauth.py
COPY ./CHANGELOG.md          /app/seacat-auth/CHANGELOG.md
COPY ./etc/message_templates /app/seacat-auth/etc/message_templates

RUN set -ex \
  && mkdir /conf \
  && touch /conf/seacatauth.conf

CMD ["python3", "seacatauth.py", "-c", "/conf/seacatauth.conf"]
