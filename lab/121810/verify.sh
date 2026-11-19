#!/bin/sh
# CVE-2026-121810 lab — bounded verification harness (S4: Docker-only).
#
# Honest-status semantics: CVE-2026-121810 is publicly NOT reproduced
# (Censys: "Not reproduced"; this lab's hunt to date is also negative —
# see README.md). So this harness does NOT fail when the vulnerable
# build survives; it asserts the LAB works and reports any crash/ASAN
# evidence verbatim when present:
#   1. all six services healthy (incl. the ASAN ASLR-lottery entrypoint),
#   2. the H3 client completes real QUIC+H3 GETs on all four nginx
#      variants (stack sanity),
#   3. the drain-saturation trigger matrix runs on vuln-asan and
#      produces drain events ("reusing connections") — the precondition
#      for the race — with client verdicts reported,
#   4. fixed-asan under the identical trigger produces ZERO reports
#      (differential integrity),
#   5. stock vuln/fixed: worker-death deltas reported; fixed must stay
#      death-free; a vuln death (if it ever lands) is printed verbatim.
#
# Everything bounded: compose up/build under timeout 600, every trigger
# run under timeout 120 (the client itself is timeout-safe: asyncio
# timeouts per attempt plus a SIGALRM watchdog).
#
# Runtime ~3-4 min. Exit 0 = lab functional (see README for verdict
# semantics of the race itself).

set -u
cd "$(dirname "$0")"

FAIL=0
logcount() { docker compose logs --since 30m "$1" 2>&1 | grep -c "$2" || true; }
step() { printf '\n=== %s ===\n' "$1"; }

step "build + start all services (bounded)"
timeout 600 docker compose up -d --build --wait \
    || { echo "FAIL: compose up --wait"; exit 1; }

step "1. H3 stack sanity — one QUIC GET on each variant"
for svc in vuln fixed vuln-asan fixed-asan; do
    out=$(timeout 120 docker compose exec -T probe python /poc/121810/trigger.py \
        --target "$svc:443" --gets 2 --repeat 1 2>&1 | grep SUMMARY)
    echo "$svc: $out"
    case "$out" in
        *TRIGGER-OK=1*) ;;
        *) echo "FAIL: $svc H3 sanity"; FAIL=1 ;;
    esac
done

step "2. drain-saturation trigger matrix on vuln-asan (evidence floor)"
b_asan=$(logcount vuln-asan "heap-use-after-free")
b_death=$(logcount vuln-asan "exited on signal")
b_drain=$(logcount vuln-asan "reusing connections")
timeout 120 docker compose exec -T probe python /poc/121810/trigger.py \
    --target vuln-asan:443 --path /refused --gets 2 --idle 12 --h1 8 \
    --burst 4 --jitter 20 --repeat 10 2>&1 | tail -1
timeout 120 docker compose exec -T probe python /poc/121810/trigger.py \
    --target vuln-asan:443 --gets 2 --idle 12 --h1 8 \
    --burst 4 --jitter 20 --repeat 10 2>&1 | tail -1
a_asan=$(logcount vuln-asan "heap-use-after-free")
a_death=$(logcount vuln-asan "exited on signal")
a_drain=$(logcount vuln-asan "reusing connections")
echo "vuln-asan: drains before/after: $b_drain -> $a_drain; \
ASAN reports: $((a_asan - b_asan)); worker deaths: $((a_death - b_death))"
if [ "$a_drain" -le "$b_drain" ]; then
    echo "FAIL: no drain events fired — saturation pressure broken"; FAIL=1
else
    echo "PASS: drain events firing (precondition for the race present)"
fi
if [ "$a_asan" -gt "$b_asan" ] || [ "$a_death" -gt "$b_death" ]; then
    echo "=== FIRST-EVIDENCE (verbatim) ==="
    timeout 30 docker compose logs vuln-asan --tail 200 2>&1 \
        | grep -A25 "ERROR: AddressSanitizer" | head -30
    timeout 30 docker compose logs vuln-asan --tail 200 2>&1 \
        | grep -E "exited on signal" | tail -3
else
    echo "INFO: no ASAN report / worker death — race not landed (matches public state)"
fi

step "3. fixed-asan differential — identical trigger, zero reports expected"
fb_asan=$(logcount fixed-asan "heap-use-after-free")
fb_death=$(logcount fixed-asan "exited on signal")
timeout 120 docker compose exec -T probe python /poc/121810/trigger.py \
    --target fixed-asan:443 --path /refused --gets 2 --idle 12 --h1 8 \
    --burst 4 --jitter 20 --repeat 10 2>&1 | tail -1
timeout 120 docker compose exec -T probe python /poc/121810/trigger.py \
    --target fixed-asan:443 --gets 2 --idle 12 --h1 8 \
    --burst 4 --jitter 20 --repeat 10 2>&1 | tail -1
fa_asan=$(logcount fixed-asan "heap-use-after-free")
fa_death=$(logcount fixed-asan "exited on signal")
echo "fixed-asan: ASAN reports: $((fa_asan - fb_asan)); worker deaths: $((fa_death - fb_death))"
if [ "$fa_asan" -gt "$fb_asan" ] || [ "$fa_death" -gt "$fb_death" ]; then
    echo "FAIL: fixed-asan reported — differential broken"; FAIL=1
else
    echo "PASS: fixed-asan clean under identical trigger"
fi

step "4. stock pair — worker-death watch"
vb_death=$(logcount vuln "exited on signal")
fx_b_death=$(logcount fixed "exited on signal")
timeout 120 docker compose exec -T probe python /poc/121810/trigger.py \
    --target vuln:443 --gets 2 --idle 12 --h1 8 --burst 4 --jitter 20 \
    --repeat 10 2>&1 | tail -1
va_death=$(logcount vuln "exited on signal")
vfx_death=$(logcount fixed "exited on signal")
timeout 120 docker compose exec -T probe python /poc/121810/trigger.py \
    --target fixed:443 --gets 2 --idle 12 --h1 8 --burst 4 --jitter 20 \
    --repeat 10 2>&1 | tail -1
vfx2_death=$(logcount fixed "exited on signal")
echo "stock vuln: worker deaths $((va_death - vb_death)); \
stock fixed: worker deaths $((vfx2_death - fx_b_death))"
if [ "$va_death" -gt "$vb_death" ]; then
    echo "=== STOCK CRASH EVIDENCE (verbatim) ==="
    timeout 30 docker compose logs vuln --tail 100 2>&1 \
        | grep -E "exited on signal|segfault" | tail -3
fi
if [ "$vfx2_death" -gt "$fx_b_death" ]; then
    echo "FAIL: stock fixed build died under trigger"; FAIL=1
else
    echo "PASS: stock fixed control death-free"
fi

step "5. worker-safety grep (all four)"
for svc in vuln fixed vuln-asan fixed-asan; do
    n=$(logcount "$svc" "exited on signal")
    echo "$svc: $n worker death line(s) total this session"
done

printf '\n==== verify: %s ====\n' "$([ "$FAIL" -eq 0 ] && echo PASS || echo FAIL)"
exit "$FAIL"
