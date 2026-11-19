#!/usr/bin/env bash
# CVE-2026-123007 lab verification harness (R3-no-harness).
#
# Builds and brings the differential lab up (gated on the compose
# healthchecks), runs the safe oracle matrix with --confirm, asserts the
# three expected verdicts, and checks that no nginx worker died.
# Prints PASS/FAIL and exits 0 only on PASS. Everything runs in Docker (S4).
#
# RUN_CRASH=1 additionally runs the crash PoC matrix (poc/crash.py) AFTER
# the oracle matrix: TLS controls first (fixed must die inside the ritual,
# mitigated must refuse h2), then the intentional vuln worker kill (~3 min:
# ~10 GiB of priming downloads + the ~52 GiB WINDOW_UPDATE flood + trigger).
# The long flood stays opt-in — the default run must remain fast.
set -euo pipefail
cd "$(dirname "$0")"

expected_vuln=VULNERABLE
expected_fixed=PATCHED
expected_mitigated=NOT-H2

echo "== build + bring up (waits for healthchecks) =="
docker compose up -d --build --wait

echo "== oracle matrix (diagnose.py --confirm) =="
# || true: a non-zero oracle exit must not abort the script — the verdict
# greps below are the judges.
out="$(docker compose exec -T probe python /poc/diagnose.py --confirm)" || true
printf '%s\n' "$out"

fail=0

check() {
    local target="$1" want="$2"
    if printf '%s\n' "$out" | grep -Eq "^\[${target}\] ${want}( |$)"; then
        echo "verdict ${target}: ${want} — ok"
    else
        echo "verdict ${target}: expected ${want}, NOT found — FAIL"
        fail=1
    fi
}
check vuln:8080 "$expected_vuln"
check fixed:8080 "$expected_fixed"
check mitigated:8080 "$expected_mitigated"

# --- crash PoC matrix (opt-in; RUN_CRASH=1) -------------------------------
# Controls first (crash.py default order), then the vuln kill.  The
# worker-safety grep below excludes `vuln` in this mode: its death is the
# asserted, intentional outcome above.
crash_safety="vuln fixed"
if [ "${RUN_CRASH:-0}" = "1" ]; then
    echo "== crash PoC matrix (crash.py; the vuln flood takes ~3 min) =="
    crash_out="$(docker compose exec -T probe python /poc/crash.py)" || true
    printf '%s\n' "$crash_out"

    crash_check() {
        local target="$1" want="$2"
        if printf '%s\n' "$crash_out" | grep -Eq "^\[${target}\] ${want}( |$)"; then
            echo "crash verdict ${target}: ${want} — ok"
        else
            echo "crash verdict ${target}: expected ${want}, NOT found — FAIL"
            fail=1
        fi
    }
    crash_check fixed:443 SURVIVED
    crash_check mitigated:443 NOT-H2
    crash_check vuln:443 WORKER-DIED

    echo "== crash server-side evidence (vuln worker death, last 10m) =="
    if docker compose logs --since 10m vuln 2>&1 \
        | grep -E 'worker process .* exited on signal 11|segfault'; then
        echo "vuln worker-death evidence found — ok"
    else
        echo "expected vuln worker-death evidence, NOT found — FAIL"
        fail=1
    fi
    crash_safety="fixed mitigated"
else
    echo "== crash PoC matrix: skipped (opt-in via RUN_CRASH=1 ./verify.sh) =="
fi

echo "== worker safety (no signal/exited/segfault in the last 5m) =="
# With RUN_CRASH=1 the vuln worker was killed ON PURPOSE (asserted above);
# the safety grep then covers only the controls.
if docker compose logs --since 5m $crash_safety 2>&1 | grep -E 'signal|exited|segfault'; then
    echo "worker-death evidence found — FAIL"
    fail=1
else
    echo "no worker deaths — ok"
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS"
else
    echo "FAIL"
    exit 1
fi
