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
    git+https://github.com/TeskaLabs/asab.git \
&& apk del buildenv

COPY seacatauth /app/seacatauth
COPY seacatauth.py /app
COPY ./CHANGELOG.md /CHANGELOG.md

RUN set -ex \
  && mkdir /conf \
  && touch /conf/seacatauth.conf

COPY etc/message_templates /app/etc/message_templates

WORKDIR /app

CMD ["python3", "seacatauth.py", "-c", "/conf/seacatauth.conf"]
