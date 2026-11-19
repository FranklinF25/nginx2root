# Source-built NGINX at a pinned release, for the CVE-2026-123007 lab.
# Nothing here runs on the host (S4): build and runtime stay in Docker.
#
# TOFU pin, computed 2026-11-19 over HTTPS from Docker Hub:
#   debian:bookworm-slim @ sha256:734a72b3d... (full digest below)
FROM debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

ARG NGINX_VERSION=1.31.8
# sha256 of https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz —
# required; the build fails on mismatch (R1-unverified-upstream-artifacts).
# docker-compose passes one digest per service alongside the version.
ARG NGINX_TARBALL_SHA256=

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl build-essential \
        libpcre2-dev zlib1g-dev libssl-dev openssl \
    && rm -rf /var/lib/apt/lists/*

# Download, verify the tarball digest, then build. No unverified bytes
# from nginx.org ever reach ./configure.
RUN set -eu \
    && test -n "${NGINX_TARBALL_SHA256}" \
        || { echo "ERROR: NGINX_TARBALL_SHA256 build arg is required" >&2; exit 1; } \
    && curl -fsSL --connect-timeout 10 --max-time 120 --retry 3 "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -o /tmp/nginx.tar.gz \
    && printf '%s  %s\n' "${NGINX_TARBALL_SHA256}" /tmp/nginx.tar.gz | sha256sum -c - \
    && tar xzf /tmp/nginx.tar.gz -C /tmp \
    && cd "/tmp/nginx-${NGINX_VERSION}" \
    && ./configure \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/dev/stderr \
        --http-log-path=/dev/stdout \
        --pid-path=/tmp/nginx.pid \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-http_stub_status_module \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /tmp/nginx*

# Self-signed lab certificate for the TLS/h2 listener
RUN mkdir -p /etc/nginx/certs \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -subj "/CN=lab.nginx2root.local" \
        -keyout /etc/nginx/certs/lab.key \
        -out /etc/nginx/certs/lab.crt

# 64 MiB of servable body so response DATA can be queued against a
# zero-sized stream window.
RUN mkdir -p /var/www \
    && dd if=/dev/zero of=/var/www/big.bin bs=1M count=64 status=none

# The real nginx.conf is volume-mounted by docker-compose (h2 vs h2-off).
STOPSIGNAL SIGQUIT
EXPOSE 8080 443
CMD ["nginx", "-g", "daemon off;"]
