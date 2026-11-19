"""Minimal stdlib-only HTTP/2 client for CVE-2026-123007 lab probes.

No third-party dependencies: it must run inside the bare python:3.12-slim
probe container (S4: Docker-only). Implements just enough of RFC 7540 to
drive nginx's connection-level flow-control accounting: SETTINGS,
WINDOW_UPDATE, PING, RST_STREAM, HEADERS (literal HPACK, no Huffman) and
GOAWAY parsing.
"""

from __future__ import annotations

import socket
import ssl
import struct

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

DATA = 0x0
HEADERS = 0x1
RST_STREAM = 0x3
SETTINGS = 0x4
PING = 0x6
GOAWAY = 0x7
WINDOW_UPDATE = 0x8

FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4

SETTINGS_INITIAL_WINDOW_SIZE = 0x4

ERR_NO_ERROR = 0x0
ERR_FLOW_CONTROL_ERROR = 0x3
ERR_CANCEL = 0x8

# nginx: NGX_HTTP_V2_MAX_WINDOW == (1U << 31) - 1
H2_MAX_WINDOW = (1 << 31) - 1
H2_DEFAULT_CONN_WINDOW = 65535


def build_frame(ftype: int, flags: int, stream_id: int, payload: b"") -> bytes:
    return (
        struct.pack(">I", len(payload))[1:]
        + bytes((ftype, flags))
        + struct.pack(">I", stream_id & 0x7FFFFFFF)
        + payload
    )


def parse_frame(buf: bytes):
    """Parse one frame from buf; return (frame_dict, consumed) or (None, 0)."""
    if len(buf) < 9:
        return None, 0
    length = struct.unpack(">I", b"\x00" + buf[0:3])[0]
    if len(buf) < 9 + length:
        return None, 0
    ftype, flags = buf[3], buf[4]
    sid = struct.unpack(">I", buf[5:9])[0] & 0x7FFFFFFF
    payload = buf[9 : 9 + length]
    f = {"type": ftype, "flags": flags, "sid": sid, "len": length, "payload": payload}
    if ftype == GOAWAY and length >= 8:
        f["last_sid"] = struct.unpack(">I", payload[0:4])[0] & 0x7FFFFFFF
        f["error"] = struct.unpack(">I", payload[4:8])[0]
    if ftype == WINDOW_UPDATE and length == 4:
        f["increment"] = struct.unpack(">I", payload)[0] & 0x7FFFFFFF
    return f, 9 + length


def hpack_literal(name: str, value: str) -> bytes:
    out = bytearray(b"\x00")  # literal without indexing, new name, no Huffman
    n, v = name.encode(), value.encode()
    assert len(n) < 127 and len(v) < 127
    out.append(len(n))
    out += n
    out.append(len(v))
    out += v
    return bytes(out)


def get_headers_block(path: str, authority: str, scheme: str = "http") -> bytes:
    return (
        hpack_literal(":method", "GET")
        + hpack_literal(":path", path)
        + hpack_literal(":scheme", scheme)
        + hpack_literal(":authority", authority)
    )


class H2Client:
    """Blocking client with explicit control over read/write behavior."""

    def __init__(self, host: str, port: int, tls: bool = False, timeout: float = 5.0,
                 rcvbuf: int | None = 65536):
        self.raw = socket.create_connection((host, port), timeout=timeout)
        if rcvbuf is not None:
            # Bound our receive buffer so the amount of response DATA that
            # drains into the kernel during the clog stays small and roughly
            # deterministic (the oracle's arithmetic depends on it).
            self.raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            self.sock = ctx.wrap_socket(self.raw, server_hostname=host)
        else:
            self.sock = self.raw
        self.buf = b""
        self.frames: list[dict] = []
        self.eof = False

    # -- low level ---------------------------------------------------------

    def send(self, data: bytes, dontwait: bool = False) -> int:
        if dontwait:
            old = self.sock.gettimeout()
            self.sock.setblocking(False)
            try:
                return self.sock.send(data)
            except BlockingIOError:
                return 0
            finally:
                self.sock.setblocking(True)
                self.sock.settimeout(old)
        return self.sock.send(data)

    def send_frame(self, ftype: int, flags: int, sid: int, payload: bytes = b"") -> int:
        return self.send(build_frame(ftype, flags, sid, payload))

    def fill(self, timeout: float = 0.2) -> None:
        """Read whatever is available into the buffer (non-destructive parse later).

        Reads until `timeout` of idleness, so a long-enough timeout also works
        as a drain. Sets self.eof when the peer closes the connection.
        """
        self.sock.settimeout(timeout)
        try:
            while True:
                chunk = self.sock.recv(65536)
                if not chunk:
                    self.eof = True
                    break
                self.buf += chunk
        except (socket.timeout, TimeoutError):
            pass
        except ConnectionResetError:
            self.eof = True

    def parse_buffered(self) -> list[dict]:
        out = []
        while True:
            f, used = parse_frame(self.buf)
            if f is None:
                break
            self.buf = self.buf[used:]
            out.append(f)
        self.frames.extend(out)
        return out

    # -- protocol steps ----------------------------------------------------

    def handshake(self, initial_window: int | None = None) -> list[dict]:
        settings = b""
        if initial_window is not None:
            settings += struct.pack(">HI", SETTINGS_INITIAL_WINDOW_SIZE, initial_window)
        self.send(PREFACE + build_frame(SETTINGS, 0, 0, settings))
        got = []
        stale = 0
        for _ in range(50):  # bounded: never spin on a broken/mute peer
            before = len(self.buf)
            self.fill()
            for f in self.parse_buffered():
                if f["type"] == SETTINGS and not f["flags"] & FLAG_ACK:
                    self.send_frame(SETTINGS, FLAG_ACK, 0)
                got.append(f)
            # stop once we saw the server SETTINGS and its ACK of ours
            acked = any(f["type"] == SETTINGS and f["flags"] & FLAG_ACK for f in got)
            served = any(f["type"] == SETTINGS and not f["flags"] & FLAG_ACK for f in got)
            if acked and served:
                break
            if len(self.buf) == before:
                stale += 1
                if stale >= 3:  # mute peer (e.g. an HTTP/1 listener): give up
                    break
            else:
                stale = 0
        return got

    def open_stream(self, sid: int, path: str, authority: str) -> None:
        block = get_headers_block(path, authority)
        self.send_frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, sid, block)

    def window_update(self, sid: int, increment: int) -> None:
        assert 0 < increment <= H2_MAX_WINDOW
        self.send_frame(WINDOW_UPDATE, 0, sid, struct.pack(">I", increment))

    def rst(self, sid: int, err: int = ERR_CANCEL) -> None:
        self.send_frame(RST_STREAM, 0, sid, struct.pack(">I", err))

    def ping(self, opaque: bytes = b"nginx2r!") -> None:
        self.send_frame(PING, 0, 0, opaque)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass
