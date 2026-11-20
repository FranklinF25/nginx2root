# lab/123633 — CVE-2026-123633 (HTTP/2 connection-draining use-after-free)

**Honest status: MECHANISM REPRODUCED (client-observable differential on
all four builds); TERMINAL UAF NOT YET LANDED** — no ASAN
heap-use-after-free report and no stock worker crash in ~200 race
attempts across the matrix below (public parity target: Censys reports
a stock worker crash on 1.31.8; we do not reach it). What IS reproduced
is the CVE window itself, differentially and on the server side
verbatim: on vulnerable 1.31.8 an **active h2 connection carrying an
in-flight proxied request sits in the reusable-connection queue and the
connection drain selects it mid-request, invoking its read handler with
`c->close = 1` inside `ngx_event_connect_peer`'s stack**; on fixed
1.31.9 this can never happen (the fix un-marks the connection the
moment a stream opens). The one step not yet lanced is making the
dead-socket detection (failing GOAWAY write / EOF recv) fire INSIDE
that drain-invoked handler — a sub-millisecond race this lab's client
cannot yet hit deterministically (details under *What remains*).

## Mechanism (source-verified on 1.31.8 vs 1.31.9 + trace-verified in this lab)

Two listeners share one worker's `worker_connections` slot pool: 8080
(plain HTTP/1: healthcheck, stub_status, busy-pressure `/slow`) and
9443 (TLS + h2: the CVE surface, `proxy_pass` upstreams).

The drain machinery (`src/core/ngx_connection.c`, 1.31.8 — this
corrects the older comments in this repo's prior labs):

- `ngx_get_connection()` calls `ngx_drain_connections()` on **every**
  allocation; the drain acts when `free_connection_n <=
  worker_connections/16` (WC=32 → free ≤ 2).
- `ngx_reusable_connection(c, 1)` inserts at the queue **head**
  (newest at head); `ngx_drain_connections()` takes `ngx_queue_last()`
  — the **least-recently-marked** — up to `max(min(32, reusable_n/8),
  1)` victims, setting `c->close = 1` and invoking
  `c->read->handler(c->read)`. A tail-hack re-drains the last victim
  once more if the free list is still empty ("reusing connection
  again").
- Victim order is therefore oldest-mark-first. An idle-filler accept
  near the threshold sacrifices ~3 old fillers per accept — **idle
  fillers are self-defeating pressure**; this lab uses busy (unread,
  never-reusable) `/slow` h1 requests instead, each holding two slots
  (client + upstream).

The bug (`src/http/v2/ngx_http_v2.c`, 1.31.8):

- `ngx_http_v2_handle_connection()` reaches
  `ngx_reusable_connection(c, 1)` and **only then** checks
  `h2c->state.incomplete`, returning early: the connection is left
  marked, with the **normal read handler** installed and the h2c pool
  alive.
- Trace-verified nuance: an incomplete **HEADERS payload** does NOT
  produce that mark (that dispatch returns before it), but an
  incomplete **SETTINGS** frame does — the trigger queues one behind a
  busy-holder stream.
- Nothing removes the mark when a stream later opens: 1.31.8 calls
  `ngx_reusable_connection(c, 0)` only in `ngx_http_v2_init()` and the
  idle handler. The entire 1.31.9 fix is two added lines in
  `ngx_http_v2_create_stream()`:
  `h2c->processing++; ngx_reusable_connection(h2c->connection, 0);`

The trigger interleave (see `poc/123633/trigger.py`):

1. handshake, then ONE write: a complete HEADERS opening stream 1 =
   `GET /slow?ms=N` (busy holder: `processing=1` keeps the connection
   out of the queue through the pressure phase) **followed by an
   incomplete client SETTINGS frame** (6-byte payload declared, 3
   bytes sent → `state.incomplete=1` saved behind the stream).
2. busy pressure: `--pressure-hold` unread `/slow` h1 requests
   (default 14 = two slots each → free = 1 at WC=32).
3. the holder completes: stream 1 closes, that dispatch ends with
   `processing=0` + `incomplete=1` → **the connection is
   reusable-marked now** (with only busy conns around it is the sole,
   i.e. oldest, mark).
4. the completion write: SETTINGS rest + HEADERS on stream 3 (`+
   stream 5` pipelined for the second-drain shape). The stream opens
   with the stale mark still on the connection (1.31.8 never un-marks
   in `create_stream`), the request runs `proxy_pass` →
   `ngx_event_connect_peer()` → `ngx_get_connection()` → the drain
   fires synchronously, selects the h2 connection and invokes its read
   handler with `c->close=1` mid-request:
   - socket alive → the handler **sends GOAWAY (last sid = the active
     stream) and returns; the client observes GOAWAY BEFORE the
     response data** — the oracle;
   - socket dead (client RST/FIN) → the intended path:
     failing GOAWAY write or EOF recv → `ngx_http_v2_finalize_connection()`
     → per-stream `ngx_http_v2_close_stream()` → `ngx_http_free_request()`
     + `ngx_destroy_pool()` — the request pool (including `u->peer`
     that `ngx_event_connect_peer` still uses) freed under the
     caller's stack; back in `ngx_event_connect_peer`,
     `pc->connection = c` writes through the freed pool: the UAF.

## Evidence of record (verbatim, debug build)

The full kill chain on `vuln` (1.31.8), trigger stream 3, single
attempt (`docker compose logs vuln`):

```text
http2 close stream 1, queued 0, processing 1     <- holder stream closes
http2 handle connection handler
reusable connection: 1                           <- THE BUG MARK (incomplete=1, processing=0)
http2 request line: "GET /refused HTTP/2.0"      <- stream 3 opens STILL MARKED
reusing connection                               <- the drain selects the h2 connection
http2 send GOAWAY frame: last sid 3, error 0     <- its read handler runs mid-request
http upstream connect: -2                        <- ngx_event_connect_peer CONTINUES on the same stack
```

Differential oracle (2026-11-20, `--repeat 3` each, 12/12 clean):

| build | oracle verdict |
|---|---|
| vuln (1.31.8 stock) | VULNERABLE-STATE 3/3 |
| fixed (1.31.9 stock) | PATCHED-STATE 3/3 |
| vuln-asan | VULNERABLE-STATE 2/2 |
| fixed-asan | PATCHED-STATE 2/2 |

## Race matrix (what was tried; all under `timeout 120`)

| shape | knobs | attempts | ASAN report / worker death |
|---|---|---|---|
| single-stream, RST | rst_gap {0,0.2,0.5,1,2,5} ms, WC=32 | 48 (vuln stock) | none |
| single-stream, RST | rst_gap {0,0.5,2} ms | 18 (vuln-asan) | none |
| pad-widened parse | rst_gap {0.1..0.8} ms, pad 30 | 30 (vuln-asan) | none |
| pad-widened parse | rst_gap {0.3,0.5,1.0} ms, pad 100 | 24 (vuln-asan) | none |
| dual-stream (drain#2 skips GOAWAY send), RST | rst_gap {0.4,0.6,0.8,1.5,2.5,4} ms, pad 20 | 70 (vuln-asan) | none |
| dual-stream, FIN | rst_gap {0.2,0.5,1.0,2.0} ms, pad 20 | 32 (vuln-asan) | none |
| FIN sweep, stock | rst_gap 0.4 ms, pad 20 | 10 (vuln stock) | none |
| controls | identical triggers on fixed / fixed-asan | 32 | none (differential integrity ✓) |

Notable near-miss (stock vuln, `rst_gap=0.4`, pad 20, single-stream):
the RST landed during the parse and the dispatch's next `SSL_read`
returned 0 — the EOF was detected and `ngx_http_v2_finalize_connection`
ran (stream 3 freed) — but one stack frame too late: the recv sat in
the OUTER read-handler loop, after `ngx_event_connect_peer` had
returned, so no freed-pool access followed. The unlanced window is
getting that detection INSIDE the drain-invoked handler invocation.

## What remains (for the next attempt)

1. **Sub-millisecond landing control.** The SO_LINGER-0 RST discards
   unACKed completion bytes when `rst_gap=0` (the trigger never fires),
   and lands after the drain's GOAWAY write once `rst_gap >= 0.2ms`;
   the FIN variant delivers data first but its EOF still must be
   observed by a recv that happens INSIDE the drain invocation. The
   c->close block in `ngx_http_v2_read_handler` appears to return after
   the goaway attempt rather than falling through to its recv loop —
   reading the rest of that block (1.31.8, lines ~112-170) to find a
   shape whose invocation #2 actually recvs is the highest-value next
   step. The dual-stream completion (stream 3 sends the GOAWAY in
   drain #1 so drain #2 skips the send) is already implemented
   (`trigger_flight`) for exactly that.
2. **The tail-hack path** (`reusing connection again`) needs
   `free_connection_n == 0` after the drain loop — at WC=32 the busy
   budget (2 slots each) cannot produce free==0 with an odd remainder;
   WC=33+ or one extra 1-slot consumer would enable it; the hack's
   second invocation is another chance for the in-drain recv.
3. **Censys parity** (stock 1.31.8 worker crash) presumably needs the
   same in-drain detection plus an unlucky heap layout for the
   post-free write; once ASAN lands, re-run the stock matrix with the
   winning shape at volume.

## Runbook

```sh
cd lab/123633
timeout 600 docker compose up -d --build --wait      # bring the lab up
sh verify.sh                                          # bounded verification (~4-5 min)

# oracle differential (no crash, no RST — the CVE window, observable):
timeout 120 docker compose exec -T probe python /poc/123633/trigger.py \
    --mode oracle --target vuln:9443 --path /refused --repeat 3
timeout 120 docker compose exec -T probe python /poc/123633/trigger.py \
    --mode oracle --target fixed:9443 --path /refused --repeat 3

# crash race (server-side evidence is authoritative):
timeout 120 docker compose exec -T probe python /poc/123633/trigger.py \
    --mode race --target vuln-asan:9443 --path /refused \
    --rst-gap 0.4 --headers 20 --repeat 10
docker compose logs vuln-asan --tail 50 | grep -E \
    "AddressSanitizer|exited on signal|http request count is zero"

# drain dynamics, verbatim (debug level):
LOGLEVEL=debug timeout 600 docker compose up -d --wait --force-recreate vuln
docker compose logs vuln --tail 2000 | grep -E \
    "reusable connection|reusing connection|http2 (send GOAWAY|close stream|handle connection)"

# knobs: --pressure-hold (busy conns, WC-5/2 rounded... default 14 for
# WC=32), --rst-gap ms, --close-mode rst|fin, --headers (pad count),
# --slow-ms (holder hold), WC/LOGLEVEL env for compose.
```

Honest status of the four questions this lab exists to answer:
**stock crash: NO. ASAN report: NO. fixed survives: YES (0 markers
under identical triggers; oracle PATCHED-STATE). CVE window (stale
reusable mark on an active h2 conn, drain selects it mid-request):
YES, reproduced client-side and server-side, differential on all four
builds.**
