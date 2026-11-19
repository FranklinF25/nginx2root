# lab/121810 — CVE-2026-121810 (HTTP/3/QUIC connection-draining use-after-free)

**Honest status: NOT REPRODUCED** — no ASAN report, no stock worker
death, no client-observable differential landed in ~120 race attempts
across the iteration matrix below. This matches the public state
(Censys: "Not reproduced"; docs/prior-art.md: "121810 **not
reproduced**"). What this lab ships is the differential infrastructure
(vuln/fixed × stock/ASAN), a saturation-capable race-trigger client,
and a source-level map of the mechanism that explains *why* the
obvious interleavings cannot fire — the starting point for the next
attempt, not a closed case.

## Mechanism (source-verified on 1.31.8 vs 1.31.9)

`listen 443 quic` + `http3 on` + `proxy_pass` upstream. nginx allocates
one `ngx_connection_t` for the QUIC parent and one per stream, all from
`worker_connections` (`ngx_get_connection`, which runs
`ngx_drain_connections()` on **every** allocation; the drain acts when
`free_connection_n <= connection_n/16`, closes
`max(min(32, reusable_n/8), 1)` connections **from the queue tail**
(the most recently `ngx_reusable_connection(c, 1)`-marked), by setting
`c->close = 1` and invoking `c->read->handler(c->read)`).

`src/event/quic/ngx_event_quic_streams.c` (1.31.8):

- `ngx_quic_create_stream()`: saves `reusable = c->reusable`,
  `ngx_reusable_connection(c, 0)` (un-queues the parent) **before**
  `sc = ngx_get_connection(...)` (line ~737), and inserts the stream
  into the parent's rbtree only **after** the slot exists (line ~814).
- If that allocation's drain closes a same-parent stream whose
  `ngx_quic_close_stream()` reaches the re-mark at line ~1168
  (`if (!pc->reusable && ngx_quic_can_shutdown(pc) == NGX_OK)
  ngx_reusable_connection(pc, 1)`), the check cannot see the
  being-created stream -> the parent is re-marked reusable mid-create
  and **stays reusable with an active stream** after creation.
- When that stream's request hits `proxy_pass` ->
  `ngx_event_connect_peer()` -> another `ngx_get_connection()` ->
  drain again: the now-reusable parent can be selected,
  `ngx_quic_close_connection()` closes its streams ->
  `ngx_http_free_request()` destroys the request pool (upstream `u`,
  `u->peer`) while `ngx_event_connect_peer` keeps using it — the UAF.

**The 1.31.9 fix** moves the rbtree insert before the slot allocation
(the whole 1.31.8→1.31.9 diff for this file is that move plus matching
deletes on the failure paths), so `ngx_quic_can_shutdown()` always sees
the being-created stream during the window.

### Why the obvious interleavings cannot fire (gate analysis)

For the re-mark at line 1168 to run inside the create window, the drain
must **synchronously** close a same-parent stream passing both
`ngx_quic_close_stream()` gates:

1. `recv_state != NGX_QUIC_STREAM_RECV_RECV` — the client must have
   FIN'd or RST'd the stream already, and
2. `send_state ∈ {DATA_RECVD, RESET_RECVD}` — everything the server
   sent on it must be ACKed, or the server's own RST must be ACKed.

Every stream connection the drain can close is
`ngx_reusable_connection`-marked, which for HTTP/3 happens only in
`ngx_http_v3_init_request_stream` / `ngx_http_v3_wait_request_handler`
NGX_AGAIN paths — i.e. streams **waiting for more request bytes**.
Drain-closing such a stream runs `ngx_http_v3_reset_stream` ->
`ngx_quic_do_reset_stream` -> `send_state = RESET_SENT` (gate 2 fails
until the client ACKs the RST — a round trip later), and an idle
no-FIN stream also fails gate 1 (`recv_state == RECV`). H3 streams
never reach keepalive or lingering close
(`ngx_http_finalize_connection`: `if (r->connection->quic) {
ngx_http_close_request(r, 0); return; }`), so a "finished stream,
live reusable-marked connection" state does not exist on the completed
request path either. Conclusion: the drain-side close that re-marks
the parent cannot be the *first* close of that stream; the real
interleaving must involve a second-order effect (e.g. a stream already
reset once and re-marked, or the uni/control-stream paths) that this
lab's matrix has not yet hit.

## Services

| Service | Build | h3 (udp) | Notes |
|---|---|---|---|
| `vuln` | nginx **1.31.8** source build (`--with-http_v3_module`, tarball sha256 + base digest pinned, `--with-debug`) | 127.0.0.1:29650 | also 29651 tcp/TLS, 29652 h1 |
| `fixed` | nginx **1.31.9**, same discipline | 127.0.0.1:29653 | patched control |
| `vuln-asan` | 1.31.8 + ASAN (make-time injection) | 127.0.0.1:29654 | evidence floor |
| `fixed-asan` | 1.31.9 + ASAN | 127.0.0.1:29655 | ASAN differential |
| `upstream` | pinned python stdlib (`upstream/serve.py`): `/ok`, `/slow?ms=N`, `/health` | internal only | reachable variant |
| `probe` | pinned python + **aioquic==1.2.0** (version-pinned, TOFU 2026-11-19) | — | all triggers run here |

Ports 29650-29655 (assigned range 29650-29659), loopback-only; the
probe always talks to in-network service names. The refused-upstream
variant (`/refused`) proxies to the nginx container's own
127.0.0.1:9 — no service needed.

`worker_connections` comes from the `WC` env (default 32; entrypoint
`sed`s the template), so the matrix values need no rebuild:

```sh
WC=48 docker compose up -d      # recreate with 48
```

**ASAN ASLR lottery (infra lesson):** on this high-ASLR WSL2 kernel an
ASAN-instrumented exec occasionally lands in a bad layout and
fault-loops at sanitizer init (`AddressSanitizer:DEADLYSIGNAL`
forever, no nginx banner; `setarch -R` is seccomp-blocked in Docker).
The outcome is per-exec and workers inherit the winning layout, so
`conf/entrypoint.sh` health-probes after 3 s and re-execs the master
(bounded 20 tries) until an attempt comes up healthy. Stock builds
always pass on the first try.

## Runbook

```sh
cd lab/121810
./verify.sh                       # bounded harness (~3-4 min), see below

# manual: the race trigger (all knobs in poc/121810/trigger.py)
docker compose exec probe python /poc/121810/trigger.py \
    --target vuln-asan:443 --path /refused \
    --gets 2 --idle 12 --h1 8 --burst 4 --burst-gap 30 --jitter 20 --repeat 25

# client knobs: --gets (completed GETs), --idle (partial-HEADERS
# streams held open — reusable-marked slot holders), --idle-fin (same
# + FIN-only: recv gate pre-passed), --abort (open+RST), --h1
# (keepalive pressure refiller), --burst/--burst-gap (trigger stream
# train), --jitter, --path (/proxied reachable, /refused instant
# ECONNREFUSED, /slow?ms= held upstream).

# evidence greps
docker compose logs vuln-asan 2>&1 | grep -E "ERROR: AddressSanitizer|exited on signal"
docker compose logs vuln 2>&1 | grep -E "exited on signal|segfault"
docker compose logs vuln-asan 2>&1 | grep -c "reusing connections"   # drain events
```

### verify.sh semantics (honest-status harness)

Because the CVE is not reproduced, exit code 0 means **the lab works**,
not that the bug fired: services healthy, H3 GETs complete on all four
variants, the saturation matrix produces drain events (the race
precondition) on `vuln-asan`, `fixed-asan` stays report-free under the
identical trigger (differential integrity), stock `fixed` stays
death-free, and any `vuln`-side ASAN report or worker death is printed
verbatim as first-evidence. The INFO line "race not landed (matches
public state)" is the expected outcome today.

## Iteration matrix (this hunt, 2026-11-19, WC=32 unless noted)

All on `vuln-asan` (ASAN floor) with the stock `vuln` shadow-run; the
trigger is a burst of complete proxied GETs on new streams of a
parent holding `--gets` completed GETs and `--idle` partial-HEADERS
streams, with `--h1` keepalive pressure from the same worker.

| Config (gets/idle/h1/burst) | path | repeat | verdicts | drains | ASAN/death |
|---|---|---|---|---|---|
| 8/20/10/1 + idle-fin 4 + abort 2 | /proxied | 3 | OK×3 | 0 | none |
| 4/24/12/1 + idle-fin 4 | /proxied | 3 | OK×3 | 0 | none |
| 1/6/2/1 | /proxied | 1 | OK×1 | 0 | none |
| 2/12/8/4, jitter 15 | /proxied | 8+6 | OK×14 | 3+6 | none |
| 2/12/8/4, remark pass | /refused | 10 | OK×10 | 47 | none |
| 3/14/8/8, jitter 25 | /slow?ms=1500 | 6 | TIMEOUT×6 (over-saturated: free=0, "worker_connections are not enough while handling frames") | — | none |
| 0/18/6/8, jitter 5 | /refused | 6 | TIMEOUT×5 OK×1 | — | none |
| 2/12/8/6 gap 30 | /proxied | 15 | OK×15 | 7 | none |
| 2/12/8/4 gap 30 | /proxied | 25+25 | OK×50 | ~10 | none |
| 1/20/0/4 gap 35 (pure-quic pressure) | /proxied | 15 | OK×8 TIMEOUT×7 | ~4 | none |
| verify.sh matrix (2/12/8/4) | /refused + /proxied | 20 | OK×20 | 10 | none |

Observations that shaped the hunt:

- **Drain victims are ~100% h1 keepalives** unless the idles are
  re-marked most-recently (the drain takes from the queue tail); the
  remark pass (extra partial byte per idle) moves them but the h1
  refiller re-outranks them within its tick.
- **Over-saturation is a cliff**: `free_connection_n == 0` makes
  `ngx_get_connection` return NULL — stream creation fails outright
  ("not enough while handling frames") and there is no window at all.
  The sweet spot keeps free pinned at 1-2 (for WC=32: idle 12 + h1 8).
- Deliberately delaying client ACKs (aioquic's ~25 ms ack batching) is
  what creates zombie streams whose *retirement* fires the line-1168
  re-mark — but retirement runs in ACK-frame processing, which cannot
  run inside the create window (see gate analysis).

Next angles, in order of promise: (1) instrument `can_shutdown`-adjacent
paths with a debug patch that logs the parent's reusable transitions,
to catch the real bug-state production wherever it lives; (2) uni
control-stream pressure (QPACK decoder flooding re-marks streams
cancelable); (3) two parents sharing the slot pool so one parent's
drain interleaves the other's retirements; (4) `WC=16` (threshold 1)
to make every allocation drain.

## Pinning (TOFU 2026-11-19)

Base image digest, nginx tarball sha256 build args (build fails on
mismatch), probe base digest, aioquic version pin — same discipline as
the root lab; see `Dockerfile`, `docker-compose.yml`, `probe/Dockerfile`.
