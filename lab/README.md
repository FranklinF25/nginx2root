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

Manual equivalent — probes always run *inside* the probe container and
target the in-container service names, never host ports:

```bash
cd lab && docker compose up -d --build --wait
docker compose ps

# safe pair oracle (targets default to vuln:8080 fixed:8080 mitigated:8080):
docker compose exec probe python /poc/diagnose.py
docker compose exec probe python /poc/diagnose.py --confirm   # re-run PATCHED with 2x streams
docker compose exec probe python /poc/diagnose.py vuln:8080   # any single host:port target

# crash PoC (planned — TLS target, not h2c):
docker compose exec probe python /poc/crash.py vuln:443

# worker-death evidence:
docker compose logs vuln 2>&1 | grep -E 'exited on signal|segfault'
```

`diagnose.py` exits 0 only when every target lands in
`VULNERABLE` / `PATCHED` / `NOT-H2`; `UNCLEAR` and `ERROR` targets exit 1.

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
