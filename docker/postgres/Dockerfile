# syntax=docker/dockerfile:1
# check=error=true

FROM postgres:18.7-trixie@sha256:2ea8630df176ad090ec92136dee850397c5af8781e4bcf2e4162593691c61bbc

# Install Debian's zlib fix (DSA-6613-1) until the official base includes it.
# Remove Debian's build-generated default certificate and key. PostgreSQL does not use them.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade zlib1g \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' zlib1g)" ge '1:1.3.dfsg+really1.3.1-1+deb13u1' \
    && rm -f /etc/ssl/certs/ssl-cert-snakeoil.pem /etc/ssl/private/ssl-cert-snakeoil.key \
    && rm -rf /var/lib/apt/lists/*
