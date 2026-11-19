#!/usr/bin/env bash
# CVE-2026-123007 lab verification harness (R3-no-harness).
#
# Builds and brings the differential lab up (gated on the compose
# healthchecks), runs the safe oracle matrix with --confirm (debian/glibc
# pair + musl/Alpine pair), asserts the five expected verdicts, and
# checks that no nginx worker died.
# Prints PASS/FAIL and exits 0 only on PASS. Everything runs in Docker (S4).
#
# RUN_CRASH=1 additionally runs the crash PoC matrix (poc/crash.py) AFTER
# the oracle matrix: TLS controls first (fixed must die inside the ritual,
# mitigated must refuse h2), then the intentional vuln worker kill (~3 min:
# ~10 GiB of priming downloads + the ~52 GiB WINDOW_UPDATE flood + trigger).
# The long flood stays opt-in — the default run must remain fast.
#
# The musl/Alpine pair (F2) is part of both matrices: its oracle matrix
# (fast) runs in the default path, its crash matrix (~2.5 min) inside
# RUN_CRASH=1. The debian defaults below stay untouched.
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
# Default targets (debian/glibc pair) then the musl pair (F2): one output
# buffer, five verdict greps.
out="$( { docker compose exec -T probe python /poc/diagnose.py --confirm
        docker compose exec -T probe python /poc/diagnose.py --confirm \
            vuln-musl:8080 fixed-musl:8080
      } 2>&1 )" || true
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
check vuln-musl:8080 "$expected_vuln"
check fixed-musl:8080 "$expected_fixed"

# --- crash PoC matrix (opt-in; RUN_CRASH=1) -------------------------------
# Controls first (crash.py default order), then the vuln kill. The
# worker-safety grep below excludes `vuln` in this mode: its death is the
# asserted, intentional outcome above. The musl crash matrix runs right
# after the debian one (controls first there too).
crash_safety="vuln fixed vuln-musl fixed-musl"
if [ "${RUN_CRASH:-0}" = "1" ]; then
    echo "== crash PoC matrix, debian/glibc (crash.py; the vuln flood takes ~3 min) =="
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

    echo "== crash PoC matrix, musl/Alpine (crash.py; ~2.5 min) =="
    musl_out="$(docker compose exec -T probe python /poc/crash.py \
        --target fixed-musl:443 --target vuln-musl:443)" || true
    printf '%s\n' "$musl_out"
    crash_out="$musl_out"   # crash_check greps $crash_out: point it at the
                             # musl buffer for the two checks below
    crash_check fixed-musl:443 SURVIVED
    crash_check vuln-musl:443 WORKER-DIED

    # F2 empirical result (observed twice, 2026-11-19, digest-pinned
    # alpine:3.22): the musl worker dies on signal 4 (SIGILL), not the
    # glibc pair's signal 11 (SIGSEGV) — the OOB copy faults differently
    # under musl but still kills the worker.
    echo "== crash server-side evidence (vuln-musl worker death, last 10m) =="
    if docker compose logs --since 10m vuln-musl 2>&1 \
        | grep -E 'worker process .* exited on signal 4'; then
        echo "vuln-musl worker-death evidence found (musl: SIGILL) — ok"
    else
        echo "expected vuln-musl worker-death evidence, NOT found — FAIL"
        fail=1
    fi
    crash_safety="fixed mitigated fixed-musl"
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
