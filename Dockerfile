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
    git+https://github.com/TeskaLabs/asab.git@fix/manifest-typo
# && apk del buildenv

RUN mkdir -p /app/seacat-auth

COPY ./seacatauth /app/seacat-auth/seacatauth
COPY ./seacatauth.py /app/seacat-auth/seacatauth.py
COPY ./CHANGELOG.md /app/seacat-auth/CHANGELOG.md

WORKDIR /app/seacat-auth
COPY .git /app/seacat-auth/.git

# Create a MANIFEST.json in the working directory
RUN asab-manifest.py ./MANIFEST.json

RUN rm -rf .git

# Remove build environment
RUN apk del buildenv

RUN set -ex \
  && mkdir /conf \
  && touch /conf/seacatauth.conf

COPY etc/message_templates /app/etc/message_templates

WORKDIR /app/seacat-auth

CMD ["python3", "seacatauth.py", "-c", "/conf/seacatauth.conf"]
