#!/usr/bin/env bash
# CVE-2026-123007 lab verification harness (R3-no-harness).
#
# Builds and brings the differential lab up (gated on the compose
# healthchecks), runs the safe oracle matrix with --confirm, asserts the
# three expected verdicts, and checks that no nginx worker died.
# Prints PASS/FAIL and exits 0 only on PASS. Everything runs in Docker (S4).
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

echo "== worker safety (no signal/exited/segfault in the last 5m) =="
if docker compose logs --since 5m vuln fixed 2>&1 | grep -E 'signal|exited|segfault'; then
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
