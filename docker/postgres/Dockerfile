# syntax=docker/dockerfile:1
# check=error=true

FROM postgres:18.7-trixie@sha256:2ea8630df176ad090ec92136dee850397c5af8781e4bcf2e4162593691c61bbc AS postgres-base

# gosu 1.20 updates moby/sys/user to fix CVE-2026-61801.
ENV GOSU_VERSION=1.20

FROM postgres-base AS gosu-download

# Verify the release with the signing key used by the official PostgreSQL image.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates wget; \
    arch="$(dpkg --print-architecture | awk -F- '{ print $NF }')"; \
    release="https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-${arch}"; \
    wget --quiet -O /tmp/gosu "$release"; \
    wget --quiet -O /tmp/gosu.asc "$release.asc"; \
    export GNUPGHOME="$(mktemp -d)"; \
    gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4; \
    gpg --batch --verify /tmp/gosu.asc /tmp/gosu

FROM postgres-base

COPY --from=gosu-download --chmod=0755 /tmp/gosu /usr/local/bin/gosu
RUN set -eu; \
    version="$(gosu --version)"; \
    test "${version%% *}" = "$GOSU_VERSION"; \
    gosu postgres true

# Install Debian's zlib fix (DSA-6613-1) until the official base includes it.
# Remove Debian's build-generated default certificate and key. PostgreSQL does not use them.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade zlib1g \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' zlib1g)" ge '1:1.3.dfsg+really1.3.1-1+deb13u1' \
    && rm -f /etc/ssl/certs/ssl-cert-snakeoil.pem /etc/ssl/private/ssl-cert-snakeoil.key \
    && rm -rf /var/lib/apt/lists/*
