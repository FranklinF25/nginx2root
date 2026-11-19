# lab — differential Docker pair for CVE-2026-123007

Everything builds and runs inside Docker; nothing touches the host (S4).
All published ports are bound to `127.0.0.1` only (R1-lan-reachable): the
lab is reachable from this machine, never from the LAN.

| Service | Build | Config | h2c | TLS+h2 |
|---|---|---|---|---|
| `vuln` | nginx **1.31.8** from source (tarball sha256-pinned, base image digest-pinned) | `conf/nginx-h2.conf` | 127.0.0.1:29601 | 127.0.0.1:29611 |
| `fixed` | nginx **1.31.9** from source (same pinning) | `conf/nginx-h2.conf` | 127.0.0.1:29602 | 127.0.0.1:29612 |
| `mitigated` | nginx **1.31.8** from source (same pinning) | `conf/nginx-h2off.conf` (`http2 off`) | 127.0.0.1:29603 | 127.0.0.1:29613 |
| `probe` | `python:3.12-slim` pinned by digest (stdlib only) | — | — | — |

All pins are TOFU values computed 2026-11-19 over HTTPS (base image
digest, probe image digest, and the nginx tarball sha256 passed as a
build arg — the build fails on digest mismatch).

Single worker per nginx so a worker death is unambiguous; `big.bin`
(64 MiB) gives the probe response bodies to queue against a zero-sized
stream window. Each nginx service has a curl healthcheck and `probe`
waits for all three to be healthy.

## Bring-up and verification

The oracle is shipped and validated; `verify.sh` is the one-command
regression harness:

```bash
cd lab && ./verify.sh
```

It runs `docker compose up -d --build --wait` (gated on the
healthchecks), executes the oracle matrix with `--confirm`, asserts the
three expected verdicts, and greps the nginx logs for worker deaths
(`signal|exited|segfault`). Exit code 0 / `PASS` means the lab is good.

`RUN_CRASH=1 ./verify.sh` opts in to the crash matrix afterwards (see
below); the default run stays fast and never floods.

## Crash PoC (F1, shipped)

`poc/crash.py` drives the deterministic worker-death chain over TLS
(ALPN h2) against the `:443` endpoints — same lab, same ritual, but it
*completes* the kill instead of probing the accounting:

0. **prime** — nginx 1.31.8's anti-flood heuristic
   (`total_bytes/8 > payload_bytes + 1 MiB` -> "http2 flood detected",
   `GOAWAY(NO_ERROR)`) kills a WINDOW_UPDATE-only connection within a
   few hundred MB. `payload_bytes` grows with every byte the server
   *sends*, so ~10 GiB of real `/big.bin` downloads (waves of ≤100
   streams, read to `END_STREAM`) raises the allowance to ~80 GiB for
   a few KB of client frames — enough for the 52 GiB flood with ~2 GiB
   of headroom. Measured cost: ~40 s.
1. **ritual** — the validated `staging_ritual()` imported from
   `diagnose.py` (staging on fresh stream ids above the priming ones,
   connection window granted relative to the leftover priming window).
   Vulnerable: `h2c->send_window` passes `2^31-1`; the capacity check
   `increment > MAX - send_window` underflows from here on. Patched:
   the first return is rejected and the connection ends — that is the
   `SURVIVED` control (no flood is attempted).
2. **flood** — stream-0 `WINDOW_UPDATE` frames of `0x7FFFFFFF` until
   `send_window >= 2^63`
   (`N = ceil((2^63 - (MAX + FIRST_RETURN))/0x7FFFFFFF)`, `FIRST_RETURN`
   imported from the oracle — never duplicated): ~4.29 billion frames,
   52 GiB / 55.8 GB, sent as pre-built blobs with rate/ETA telemetry
   every ~30 s; nothing is read during the flood. A pending zero-window
   stream keeps the connection non-idle. Measured: ~110 s at ~0.5 GB/s
   on a primed connection (~30 s at ~1.8 GB/s unprimed).
3. **trigger** — a fresh stream: `HEADERS GET /big.bin END_STREAM`, a
   1 MiB stream `WINDOW_UPDATE`, then a liveness PING ordered behind
   it. The filter uses the connection window as an `(off_t)` limit —
   negative past `2^63` — casts to `size_t`, and the TLS output path
   `ngx_memcpy`s a ~2^63-sized chunk (glibc huge-copy touches
   non-canonical memory): the worker takes SIGSEGV, the master
   respawns it, and the client sees the connection die with no GOAWAY
   and no PING answer.

Verdicts: `vuln:443` -> `WORKER-DIED` (client-side death after the
trigger; the probe container cannot read docker logs, so confirm on the
host: `docker compose logs --since 10m vuln 2>&1 | grep -E 'worker
process .* exited on signal 11|segfault'` — observed: `worker process
7 exited on signal 11 (core dumped)` + `start worker process 6721`).
`fixed:443` -> `SURVIVED` (terminated inside the ritual, before any
flood; on a primed connection the FIN can surface one drain later, at
the RST drain). `mitigated:443` -> `NOT-H2` (TLS alert `no application
protocol` — ALPN never offers h2).

Expected runtime: full matrix ≈ 4 min (fixed ~1 min incl. priming,
mitigated seconds, vuln ~3 min). `--max-frames N` caps the flood for
bounded smoke runs; `--target` picks single targets. Controls run
before the vuln attempt so a surprise cannot contaminate them.

`RUN_CRASH=1 ./verify.sh` runs the crash matrix after the oracle
matrix, asserts the three crash verdicts, requires the vuln
worker-death line in `vuln` logs, and re-checks that `fixed`/
`mitigated` stayed worker-death-free (the intentional vuln kill is
excluded from the generic worker-safety grep in that mode).

Manual equivalent — probes always run *inside* the probe container and
target the in-container service names, never host ports:

```bash
cd lab && docker compose up -d --build --wait
docker compose ps

# safe pair oracle (targets default to vuln:8080 fixed:8080 mitigated:8080):
docker compose exec probe python /poc/diagnose.py
docker compose exec probe python /poc/diagnose.py --confirm   # re-run PATCHED with 2x streams
docker compose exec probe python /poc/diagnose.py vuln:8080   # any single host:port target

# crash PoC (TLS :443 targets, default order fixed -> mitigated -> vuln):
docker compose exec probe python /poc/crash.py                 # full matrix (~4 min)
docker compose exec probe python /poc/crash.py --target vuln:443
docker compose exec probe python /poc/crash.py --target vuln:443 --max-frames 5000000  # capped smoke run

# worker-death evidence:
docker compose logs vuln 2>&1 | grep -E 'exited on signal|segfault'
```

`diagnose.py` exits 0 only when every target lands in
`VULNERABLE` / `PATCHED` / `NOT-H2`; `UNCLEAR` and `ERROR` targets exit 1.
`crash.py` exits 0 only on `SURVIVED` / `NOT-H2` / `WORKER-DIED`.

## Oracle verdict semantics

The probe runs in four labeled phases — `staging`, `first-return`,
`rst-drain`, `probe`. Only the peer's death *at* the first-return
WINDOW_UPDATE (observed via TCP state, without reading, or a GOAWAY
`FLOW_CONTROL_ERROR`) may be classified `PATCHED`. Death or reset in any
other phase returns `UNCLEAR` naming the phase — on the vulnerable build
that can mean a worker died mid-probe, and that must never be reported
as "patched". With `--confirm`, a `PATCHED` verdict is re-run with
double the streams and downgraded to `UNCLEAR` ("insufficient staging on
first attempt") if the target survives the second run.

## Oracle design (validated)

Per Xint §5.1: queuing DATA against `SETTINGS_INITIAL_WINDOW_SIZE = 0`,
returning credit `Q` with a stream-0 `WINDOW_UPDATE`, then canceling the
streams with `RST_STREAM` makes the vulnerable build add `Q` twice and
push `h2c->send_window` past `2^31 - 1`
(`ngx_http_v2_filter_cleanup` has no upper-bound check).

A later oversized stream-0 `WINDOW_UPDATE` then diverges without
crashing either side:

- **vulnerable** — `NGX_HTTP_V2_MAX_WINDOW - h2c->send_window`
  underflows (unsigned), the frame is accepted, the connection answers a
  follow-up PING;
- **patched** — the same frame trips `NGX_HTTP_V2_FLOW_CTRL_ERROR`, the
  connection closes with GOAWAY.

`mitigated` must refuse h2c/h2 negotiation entirely (ALPN/h2c
prior-knowledge handshake failure) — the verified-mitigation control.
