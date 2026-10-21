"""UDP DNS proxy that feeds resolved allowlist IPs into nftables sets."""

from __future__ import annotations

import logging
import re
import socket
import struct
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from buddelkiste.which import log_cmdline

log = logging.getLogger(__name__)

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

DNS_PROXY_PORT = 15353


def is_valid_hostname_pattern(value: str) -> bool:
    text = value.strip().lower().rstrip(".")
    if not text or len(text) > 253:
        return False
    if text.startswith("*."):
        text = text[2:]
        if not text or "*" in text:
            return False
    elif "*" in text:
        return False
    labels = text.split(".")
    return not any(not label or not _LABEL_RE.match(label) for label in labels)


def host_matches(qname: str, patterns: Sequence[str]) -> bool:
    name = qname.lower().rstrip(".")
    for pattern in patterns:
        pat = pattern.lower().rstrip(".")
        if pat.startswith("*."):
            suffix = pat[1:]  # leading dot + domain
            if name.endswith(suffix) and len(name) > len(suffix):
                return True
        elif name == pat:
            return True
    return False


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    start = offset
    for _ in range(128):
        if offset >= len(data):
            raise ValueError("truncated DNS name")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
            if not jumped:
                start = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset : offset + length].decode("ascii", "ignore"))
        offset += length
    return ".".join(labels), (start if jumped else offset)


def _encode_name(name: str) -> bytes:
    parts = [p for p in name.rstrip(".").split(".") if p]
    out = bytearray()
    for part in parts:
        raw = part.encode("ascii")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def extract_query(data: bytes) -> tuple[str, int] | None:
    if len(data) < 12:
        return None
    _, flags, qdcount, *_ = struct.unpack("!HHHHHH", data[:12])
    if qdcount < 1:
        return None
    # Query bit must be 0 for standard queries (QR=0).
    if flags & 0x8000:
        return None
    name, offset = _decode_name(data, 12)
    if offset + 4 > len(data):
        return None
    qtype, _qclass = struct.unpack("!HH", data[offset : offset + 4])
    return name, qtype


def extract_answer_ips(data: bytes) -> tuple[list[str], int]:
    """Return (ipv4/ipv6 texts, min TTL) from a DNS response."""
    if len(data) < 12:
        return [], 60
    _id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    if not (flags & 0x8000):
        return [], 60
    offset = 12
    for _ in range(qdcount):
        _name, offset = _decode_name(data, offset)
        offset += 4
    ips: list[str] = []
    min_ttl = None
    total = ancount + nscount + arcount
    for _ in range(total):
        if offset >= len(data):
            break
        _name, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:  # A
            ips.append(socket.inet_ntop(socket.AF_INET, rdata))
            min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
        elif rtype == 28 and rdlen == 16:  # AAAA
            ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
            min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
    return ips, 60 if min_ttl is None else max(min_ttl, 5)


def nxdomain_response(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    header = bytearray(query[:12])
    # QR=1, RCODE=NXDOMAIN (3), copy id/opcode
    flags = struct.unpack("!H", header[2:4])[0]
    flags = (flags & 0x7900) | 0x8003
    header[2:4] = struct.pack("!H", flags)
    header[6:12] = b"\x00\x00\x00\x00\x00\x00"  # no answers
    # Include original question section.
    try:
        _name, offset = _decode_name(query, 12)
        question = query[12 : offset + 4]
    except ValueError:
        question = b""
    header[4:6] = struct.pack("!H", 1 if question else 0)
    return bytes(header) + question


def _recvexact(sock: socket.socket, size: int) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < size:
        piece = sock.recv(size - len(chunks))
        if not piece:
            return None
        chunks.extend(piece)
    return bytes(chunks)


def _rcode(message: bytes) -> int | None:
    if len(message) < 4:
        return None
    return struct.unpack("!H", message[2:4])[0] & 0x000F


# Unreachable resolvers often blackhole until the TCP timeout. A short connect
# budget lets a later upstream's answer through. ``_PREFER_EARLIER_UPSTREAM`` is
# how long a higher-priority resolver may still override that answer for split-DNS.
_UPSTREAM_CONNECT_TIMEOUT = 0.2
_PREFER_EARLIER_UPSTREAM = 0.1


def _open_upstream(upstream: str, timeout: float) -> socket.socket:
    """Connect to an IP:53 resolver or an absolute Unix socket path."""
    if upstream.startswith("/"):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(upstream)
        except OSError:
            sock.close()
            raise
        return sock
    return socket.create_connection(
        (upstream, 53),
        timeout=min(_UPSTREAM_CONNECT_TIMEOUT, timeout),
    )


def _forward_one(payload: bytes, upstream: str, timeout: float) -> tuple[bytes | None, str]:
    """Query one upstream. Return ``(response, "")`` or ``(None, error)``."""
    try:
        with _open_upstream(upstream, timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            header = _recvexact(sock, 2)
            if header is None:
                return None, f"{upstream}: closed before response header"
            (length,) = struct.unpack("!H", header)
            if length == 0 or length > 65535:
                return None, f"{upstream}: invalid length {length}"
            data = _recvexact(sock, length)
            if data is None:
                return None, f"{upstream}: closed before full response body"
            return data, ""
    except OSError as exc:
        return None, f"{upstream}: {type(exc).__name__}: {exc}"


def _positive_dns(data: bytes | None) -> bool:
    if data is None:
        return False
    rcode = _rcode(data)
    return rcode not in (2, 3)


def forward_query(query: bytes, upstreams: Sequence[str], timeout: float = 1.5) -> bytes | None:
    """Forward a DNS query to an upstream resolver.

    Uses DNS-over-TCP so upstream queries are not caught by the in-namespace
    nftables UDP/53 redirect that steers guest traffic to this proxy. An
    upstream that is an absolute path is a Unix socket, used to reach the host
    resolver from inside the sandbox netns.

    Upstreams are queried together. An earlier address wins when it returns a
    usable answer, so split-DNS host resolvers stay ahead of the public
    fallbacks. A positive answer is returned once higher-priority upstreams have
    finished or ``_PREFER_EARLIER_UPSTREAM`` has passed, so a blackholed resolver
    does not hold the query for the full ``timeout``. NXDOMAIN and SERVFAIL are
    not final while another upstream can still answer.
    """
    payload = struct.pack("!H", len(query)) + query
    if not upstreams:
        log.warning("no DNS upstreams configured; answering NXDOMAIN")
        return None

    results: list[bytes | None] = [None] * len(upstreams)
    done = [False] * len(upstreams)
    lock = threading.Lock()

    def attempt(index: int, upstream: str) -> None:
        data, err = _forward_one(payload, upstream, timeout)
        if err:
            log.debug("DNS upstream %s failed: %s", upstream, err)
        with lock:
            results[index] = data
            done[index] = True

    threads = [
        threading.Thread(target=attempt, args=(index, upstream), daemon=True)
        for index, upstream in enumerate(upstreams)
    ]
    for thread in threads:
        thread.start()

    def choose(*, allow_pending: bool) -> bytes | None | object:
        negative: bytes | None = None
        for finished, data in zip(done, results, strict=True):
            if not finished:
                if allow_pending:
                    return _PENDING
                continue
            if data is None:
                continue
            if not _positive_dns(data):
                if negative is None:
                    negative = data
                continue
            return data
        return negative

    deadline = time.monotonic() + timeout
    positive_since: float | None = None
    chosen: bytes | None | object = _PENDING
    while time.monotonic() < deadline:
        with lock:
            chosen = choose(allow_pending=True)
            if chosen is not _PENDING or all(done):
                break
            ready = choose(allow_pending=False)
            if isinstance(ready, bytes) and _positive_dns(ready):
                now = time.monotonic()
                if positive_since is None:
                    positive_since = now
                elif now - positive_since >= _PREFER_EARLIER_UPSTREAM:
                    chosen = ready
                    break
            else:
                positive_since = None
        time.sleep(0.02)
    if chosen is _PENDING:
        with lock:
            chosen = choose(allow_pending=False)

    if isinstance(chosen, bytes):
        return chosen
    if upstreams:
        log.warning(
            "all DNS upstreams failed (%s); answering NXDOMAIN",
            ", ".join(upstreams),
        )
    return None


_PENDING = object()


class HostDnsRelay:
    """Forward DNS-over-TCP from a Unix socket to the host stub resolver.

    The sandbox netns cannot reach ``127.0.0.53``. This relay runs in the host
    netns, where that stub is the local systemd-resolved, and the guest proxy
    speaks to the socket instead of dialing every uplink itself.
    """

    def __init__(self, path: Path, upstream: str, port: int = 53) -> None:
        self.path = path
        self.upstream = upstream
        self.port = port
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if path.exists():
            path.unlink()
        self._sock.bind(str(path))
        path.chmod(0o600)
        self._sock.listen(32)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(
            target=self._serve,
            name="buddelkiste-dns-relay",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)
        self.path.unlink(missing_ok=True)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            with conn:
                header = _recvexact(conn, 2)
                if header is None:
                    return
                (length,) = struct.unpack("!H", header)
                if length == 0 or length > 65535:
                    return
                body = _recvexact(conn, length)
                if body is None:
                    return
                data, _err = _forward_tcp(self.upstream, self.port, header + body, 2.0)
                if data is not None:
                    conn.sendall(struct.pack("!H", len(data)) + data)
        except OSError as exc:
            log.debug("DNS relay failed: %s", exc)


def _forward_tcp(
    host: str,
    port: int,
    payload: bytes,
    timeout: float,
) -> tuple[bytes | None, str]:
    """Send one length-prefixed DNS query over TCP and return the body."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            header = _recvexact(sock, 2)
            if header is None:
                return None, f"{host}: closed before response header"
            (length,) = struct.unpack("!H", header)
            if length == 0 or length > 65535:
                return None, f"{host}: invalid length {length}"
            data = _recvexact(sock, length)
            if data is None:
                return None, f"{host}: closed before full response body"
            return data, ""
    except OSError as exc:
        return None, f"{host}: {type(exc).__name__}: {exc}"


class DnsProxy:
    """Forward UDP DNS, NXDOMAIN denied names, and publish allowed A/AAAA to nft."""

    def __init__(
        self,
        *,
        upstreams: Sequence[str],
        allow_hosts: Sequence[str],
        deny_hosts: Sequence[str],
        add_allow_ip: Callable[[str, int], None],
        listen_host: str = "127.0.0.1",
        listen_port: int = DNS_PROXY_PORT,
    ):
        self.upstreams = list(upstreams)
        self.allow_hosts = list(allow_hosts)
        self.deny_hosts = list(deny_hosts)
        self.add_allow_ip = add_allow_ip
        self.listen_host = listen_host
        self.listen_port = listen_port
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.listen_host, self.listen_port))
        sock.settimeout(0.5)
        self._sock = sock
        self._thread = threading.Thread(target=self._serve, name="buddelkiste-dns", daemon=True)
        self._thread.start()
        log.debug(
            "DNS proxy config listen=%s:%s upstreams=%s allow_hosts=%s deny_hosts=%s "
            "wildcards allow=%s deny=%s",
            self.listen_host,
            self.listen_port,
            self.upstreams,
            self.allow_hosts,
            self.deny_hosts,
            [host for host in self.allow_hosts if host.startswith("*.")],
            [host for host in self.deny_hosts if host.startswith("*.")],
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError as exc:
                if not self._stop.is_set():
                    log.warning("DNS proxy recv failed: %s", exc)
                break
            try:
                reply = self._handle(data)
                if reply:
                    self._sock.sendto(reply, addr)
            except Exception:
                log.exception("DNS proxy handler failed")

    def _handle(self, data: bytes) -> bytes | None:
        parsed = extract_query(data)
        if parsed is None:
            return None
        qname, qtype = parsed
        if self.deny_hosts and host_matches(qname, self.deny_hosts):
            return nxdomain_response(data)

        reply = forward_query(data, self.upstreams)
        if reply is None:
            return nxdomain_response(data)

        if self.allow_hosts and host_matches(qname, self.allow_hosts) and qtype in (1, 28, 255):
            ips, ttl = extract_answer_ips(reply)
            for ip in ips:
                try:
                    self.add_allow_ip(ip, ttl)
                except Exception:
                    log.exception("failed to allow resolved IP %s for %s", ip, qname)
        return reply


def nft_add_allow_ip(ip: str, ttl: int) -> None:
    """Add a resolved address to the dynamic allow set with timeout."""
    family = "allow4" if ":" not in ip else "allow6"
    # dyn sets use plain addresses (not interval).
    set_name = f"dyn_{family}"
    timeout = max(int(ttl), 5)
    cmd = [
        "nft",
        "add",
        "element",
        "inet",
        "buddelkiste",
        set_name,
        "{",
        f"{ip} timeout {timeout}s",
        "}",
    ]
    log_cmdline(cmd, label="nft")
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        log.warning("nft add element failed: %s", proc.stderr.strip() or proc.stdout.strip())
