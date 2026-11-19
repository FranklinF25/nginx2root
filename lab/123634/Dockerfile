# Source-built NGINX at a pinned release, for the CVE-2026-123634 lab
# (DNS resolver use-after-free: the resolver waiting-list walk calls
# ctx->handler after a sibling handler's ngx_http_terminate_request freed
# the sibling ctx — main request + mirror subrequest on the same resolver
# node). Nothing here runs on the host (S4): build and runtime stay in Docker.
#
# TOFU pin, computed 2026-11-19 over HTTPS from Docker Hub (same digest as
# the root 123007 lab — same base image):
#   debian:bookworm-slim @ sha256:734a72b3d...
FROM debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

ARG NGINX_VERSION=1.31.8
# sha256 of https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz —
# required; the build fails on mismatch (R1-unverified-upstream-artifacts).
# Values are the same as the root lab's (sources are shared):
#   1.31.8  0652b760b3b772d2ec17b47c2fc15d9a95e6fe35cd5b877eadc1a62d9bc75af1
#   1.31.9  a11c5eeee2e257f4478f0e649f84b0040787d277d2d3e5233952aa6b6dcb80ad
ARG NGINX_TARBALL_SHA256=
# ASAN=1 builds the instrumented variant (evidence floor: the verbatim
# heap-use-after-free report). The same configure flags otherwise; the
# runtime env comes from docker-compose (ASAN_OPTIONS=detect_leaks=0...).
ARG ASAN=0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl build-essential \
        libpcre2-dev zlib1g-dev libssl-dev openssl \
    && rm -rf /var/lib/apt/lists/*

# Download, verify the tarball digest, then configure. No unverified bytes
# from nginx.org ever reach ./configure. The configure and make steps are
# separate RUN layers so a bounded (host-side timeout) rebuild resumes from
# the configure layer instead of re-downloading and re-configuring.
RUN set -eu \
    && test -n "${NGINX_TARBALL_SHA256}" \
        || { echo "ERROR: NGINX_TARBALL_SHA256 build arg is required" >&2; exit 1; } \
    && curl -fsSL --connect-timeout 10 --max-time 120 --retry 3 "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -o /tmp/nginx.tar.gz \
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
            --with-http_ssl_module \
            --with-http_stub_status_module \
            > /tmp/configure.log 2>&1 \
           || [ "$n" -ge 5 ]; do \
           n=$((n+1)); \
           echo "configure attempt $n hung/died; retrying; last output:"; \
           tail -n 2 /tmp/configure.log; \
       done \
    && test -f Makefile \
    && tail -n 2 /tmp/configure.log

# Build. For ASAN=1 the sanitizer flags are injected at make time (sed on
# objs/Makefile) instead of at configure time: nginx's configure runs small
# test programs, and ASAN-instrumented test-exec hangs on this high-ASLR
# WSL2 kernel (and setarch -R personality(2) is blocked by Docker's default
# seccomp). The feature tests are libc/compiler probes — they do not depend
# on sanitizer semantics — while every compiled object and the final link
# still get the full instrumentation.
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

# The real nginx.conf is volume-mounted by docker-compose (same conf for
# all four services; only the binary differs).
STOPSIGNAL SIGQUIT
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
