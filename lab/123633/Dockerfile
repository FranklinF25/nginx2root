# Source-built NGINX at a pinned release, for the CVE-2026-123633 lab
# (HTTP/2 connection-draining use-after-free: an h2 connection left in
# the reusable queue with an active stream; a drain fired inside
# ngx_event_connect_peer's ngx_get_connection frees the in-flight
# request pool while the caller keeps using u->peer).
# Nothing here runs on the host (S4): build and runtime stay in Docker.
#
# TOFU pin, computed 2026-11-19 over HTTPS from Docker Hub (same base and
# same pinning day as the root CVE-2026-123007 lab):
#   debian:bookworm-slim @ sha256:734a72b3d... (full digest below)
FROM debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

ARG NGINX_VERSION=1.31.8
# sha256 of https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz —
# required; the build fails on mismatch (R1-unverified-upstream-artifacts).
# Same values as the root lab's (sources are shared):
#   1.31.8  0652b760b3b772d2ec17b47c2fc15d9a95e6fe35cd5b877eadc1a62d9bc75af1
#   1.31.9  a11c5eeee2e257f4478f0e649f84b0040787d277d2d3e5233952aa6b6dcb80ad
ARG NGINX_TARBALL_SHA256=
# ASAN=1 builds the instrumented variant (evidence floor: the verbatim
# heap-use-after-free report). Flags are injected at make time, NOT
# configure time: nginx's configure runs small test programs and
# ASAN-instrumented test-exec hangs on this high-ASLR WSL2 kernel
# (setarch -R is seccomp-blocked in Docker). The feature tests are
# libc/compiler probes; every object and the final link still get the
# full instrumentation (lesson paid for in this repo).
ARG ASAN=0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl build-essential \
        libpcre2-dev zlib1g-dev libssl-dev openssl \
    && rm -rf /var/lib/apt/lists/*

# Download (bounded curl — repo lesson #1), verify the tarball digest,
# then configure PLAIN (repo lesson #2). Configure and make are separate
# RUN layers so a bounded (host-side timeout) rebuild resumes from the
# configure layer. The retry-until wrapper guards the known
# configure-hang class of failures.
RUN set -eu \
    && test -n "${NGINX_TARBALL_SHA256}" \
        || { echo "ERROR: NGINX_TARBALL_SHA256 build arg is required" >&2; exit 1; } \
    && curl -fsSL --connect-timeout 10 --max-time 120 --retry 3 \
        "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -o /tmp/nginx.tar.gz \
    && printf '%s  %s\n' "${NGINX_TARBALL_SHA256}" /tmp/nginx.tar.gz | sha256sum -c - \
    && tar xzf /tmp/nginx.tar.gz -C /tmp \
    && cd "/tmp/nginx-${NGINX_VERSION}" \
    && n=0 \
    && until timeout 120 ./configure \
            --prefix=/etc/nginx \
            --sbin-path=/usr/sbin/nginx \
            --conf-path=/etc/nginx/nginx.conf \
            --error-log-path=/dev/stderr \
            --http-log-path=/dev/stdout \
            --pid-path=/tmp/nginx.pid \
            --with-debug \
            --with-http_ssl_module \
            --with-http_v2_module \
            --with-http_stub_status_module \
            > /tmp/configure.log 2>&1 \
           || [ "$n" -ge 5 ]; do \
           n=$((n+1)); \
           echo "configure attempt $n hung/died; retrying; last output:"; \
           tail -n 2 /tmp/configure.log; \
       done \
    && test -f Makefile \
    && tail -n 2 /tmp/configure.log

# Build: ASAN flags sed'd into objs/Makefile at make time, link with
# LINK="cc -fsanitize=address". -j4 (repo lesson #3).
RUN set -eu \
    && cd "/tmp/nginx-${NGINX_VERSION}" \
    && if [ "${ASAN}" = "1" ]; then \
           sed -i '/^CFLAGS = /s/$/ -fsanitize=address -fno-omit-frame-pointer -g/' objs/Makefile \
            && grep -m1 '^CFLAGS = ' objs/Makefile \
            && make -j4 LINK="cc -fsanitize=address"; \
       else \
           make -j4; \
       fi \
    && make install \
    && rm -rf /tmp/nginx*

# Self-signed lab certificate for the TLS+h2 listener (9443).
RUN mkdir -p /etc/nginx/certs \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -subj "/CN=lab.nginx2root.local" \
        -keyout /etc/nginx/certs/lab.key \
        -out /etc/nginx/certs/lab.crt

# The nginx.conf template is volume-mounted by docker-compose; the
# entrypoint substitutes worker_connections (WC) and the error_log level
# (LOGLEVEL) from env, so the iteration matrix needs no rebuild.
COPY conf/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
STOPSIGNAL SIGQUIT
EXPOSE 8080 9443
ENTRYPOINT ["/entrypoint.sh"]
