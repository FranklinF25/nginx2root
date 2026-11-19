# Source-built NGINX at a pinned release, for the CVE-2026-123007 lab.
# Nothing here runs on the host (S4): build and runtime stay in Docker.
FROM debian:bookworm-slim

ARG NGINX_VERSION=1.31.8

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl build-essential \
        libpcre2-dev zlib1g-dev libssl-dev openssl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -o /tmp/nginx.tar.gz \
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
