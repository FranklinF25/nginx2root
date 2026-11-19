# lab — differential Docker pair for CVE-2026-123007

Everything builds and runs inside Docker; nothing touches the host (S4).

| Service | Build | Config | h2c | TLS+h2 |
|---|---|---|---|---|
| `vuln` | nginx **1.31.8** from source | `conf/nginx-h2.conf` | :29601 | :29611 |
| `fixed` | nginx **1.31.9** from source | `conf/nginx-h2.conf` | :29602 | :29612 |
| `mitigated` | nginx **1.31.8** from source | `conf/nginx-h2off.conf` (`http2 off`) | :29603 | :29613 |
| `probe` | `python:3.12-slim` (stdlib only) | — | — | — |

Single worker per nginx so a worker death is unambiguous; `big.bin`
(64 MiB) gives the probe response bodies to queue against a zero-sized
stream window.

## Bring-up

```bash
cd lab && docker compose up -d --build
docker compose ps

# probes always run inside the probe container:
docker compose exec probe python /poc/diagnose.py            # safe pair oracle (planned)
docker compose exec probe python /poc/crash.py 29601 80      # worker-death PoC (planned)

# worker-death evidence:
docker compose logs vuln 2>&1 | grep -E 'exited on signal|segfault'
```

## Oracle design (working hypothesis, to be validated empirically)

Per Xint §5.1: queuing DATA against `SETTINGS_INITIAL_WINDOW_SIZE = 0`,
returning credit `Q` with a stream-0 `WINDOW_UPDATE`, then canceling the
streams with `RST_STREAM` makes the vulnerable build add `Q` twice and
push `h2c->send_window` past `2^31 - 1` (`ngx_http_v2_filter_cleanup`
has no upper-bound check).

A later oversized stream-0 `WINDOW_UPDATE` then diverges without
crashing either side:

- **vulnerable** — `NGX_HTTP_V2_MAX_WINDOW - h2c->send_window`
  underflows (unsigned), the frame is accepted, the connection answers a
  follow-up PING;
- **patched** — the same frame trips `NGX_HTTP_V2_FLOW_CTRL_ERROR`, the
  connection closes with GOAWAY.

`mitigated` must refuse h2c/h2 negotiation entirely (ALPN/h2c
prior-knowledge handshake failure) — the verified-mitigation control.
