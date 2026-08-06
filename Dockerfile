# ---- Build stage ----
FROM alpine:3.24 AS builder
LABEL maintainer="TeskaLabs Ltd (support@teskalabs.com)"

ENV LANG=C.UTF-8

# Install uv (static binary)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

RUN set -ex \
  && apk update \
  && apk upgrade

RUN apk add --no-cache \
  python3 \
  libstdc++ \
  openssl \
  xmlsec \
  openldap

# Create build environment so that dependencies like aiohttp can be built
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
    cargo

# Create virtual environment
RUN python3 -m venv /venv

RUN mkdir -p /app/seacat-auth
WORKDIR /app/seacat-auth
COPY . /app/seacat-auth

# Install main deps + ldap into /venv (uses uv.lock when present)
ENV UV_PROJECT_ENVIRONMENT=/venv
ENV UV_LINK_MODE=copy
RUN uv sync --extra ldap --frozen --no-cache --no-editable

# This is for github CI/CD logs
RUN /venv/bin/python3 -c "import asab; print(asab.__version__)"

# Create MANIFEST.json in the working directory
# The manifest script needs the entire repo in a clean state (to avoid the -dirty tag)
RUN /venv/bin/asab-manifest.py ./MANIFEST.json


# ---- Runtime stage ----
FROM alpine:3.24

RUN apk add --no-cache \
  python3 \
  openssl \
  xmlsec \
  openldap

COPY --from=builder /venv /venv

COPY ./seacatauth            /app/seacat-auth/seacatauth
COPY ./scripts/ldap-access-sync.py  /app/seacat-auth/scripts/ldap-access-sync.py
COPY ./seacatauth.py         /app/seacat-auth/seacatauth.py
COPY ./CHANGELOG.md          /app/seacat-auth/CHANGELOG.md
COPY --from=builder /app/seacat-auth/MANIFEST.json /app/seacat-auth/MANIFEST.json

COPY ./etc/message_templates /app/seacat-auth/etc/message_templates

RUN set -ex \
  && mkdir /conf \
  && touch /conf/seacatauth.conf

WORKDIR /app/seacat-auth
ENV PATH="/app/seacat-auth/scripts:/venv/bin:$PATH"
CMD ["python3", "seacatauth.py", "-c", "/conf/seacatauth.conf"]
