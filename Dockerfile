# ---- Build stage ----
FROM alpine:3.24 AS builder
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
  xmlsec \
  openldap

# Create build environment so that dependencies like aiohttp can be built
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
    cargo

# Create virtual environment
RUN python3 -m venv /venv \
    && /venv/bin/pip3 install --upgrade pip

RUN mkdir -p /app/seacat-auth
RUN mkdir -p /app/seacat-auth/scripts
WORKDIR /app/seacat-auth

# Copy project metadata files first for better layer caching
COPY README.md pyproject.toml /app/seacat-auth/

# Copy the source code
COPY seacatauth /app/seacat-auth/seacatauth
COPY seacatauth.py /app/seacat-auth/seacatauth.py

# Install using pip with pyproject.toml (includes all main deps + ldap extra)
RUN /venv/bin/pip3 install --no-cache-dir ".[ldap]"

# Verify ASAB version
RUN /venv/bin/python -c "import asab; print(asab.__version__)"

# Create MANIFEST.json in the working directory
# The manifest script requires git to be installed
COPY ./.git /app/seacat-auth/.git
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
