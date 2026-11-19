#!/bin/sh
# Substitute worker_connections from $WC (default 32) into the mounted
# conf template, then run nginx in the foreground.
#
# ASAN lottery retry: on this high-ASLR WSL2 kernel an ASAN-instrumented
# exec occasionally lands in a bad address layout and fault-loops at
# sanitizer init ("AddressSanitizer:DEADLYSIGNAL" forever, no nginx
# banner; setarch -R is seccomp-blocked in Docker so ASLR can't just be
# disabled). The outcome is per-exec: nginx workers inherit the winning
# layout, so the robust fix is to detect the fault-loop and re-exec the
# master until an attempt comes up healthy. Stock builds always pass on
# the first try; the loop is bounded (20 x 3 s) so bring-up stays bounded.
set -u
WC="${WC:-32}"
sed "s/__WC__/${WC}/" /etc/nginx/nginx.conf.tmpl > /tmp/nginx.conf

i=0
while [ "$i" -lt 20 ]; do
    nginx -c /tmp/nginx.conf -g 'daemon off;' &
    MPID=$!
    sleep 3
    if curl -fsS -m 2 http://127.0.0.1:8080/health >/dev/null 2>&1; then
        trap 'kill -QUIT "$MPID" 2>/dev/null; wait "$MPID"; exit 0' TERM INT QUIT
        wait "$MPID"
        exit $?
    fi
    echo "entrypoint: nginx unhealthy after 3s (attempt $i) — ASAN ASLR lottery? re-exec" >&2
    kill -QUIT "$MPID" 2>/dev/null
    kill -TERM "$MPID" 2>/dev/null
    wait "$MPID" 2>/dev/null
    i=$((i + 1))
done
echo "entrypoint: giving up after $i attempts" >&2
exit 1
