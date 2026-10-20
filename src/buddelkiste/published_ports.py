"""Relay host-published container ports onto the sandbox loopback.

Filter mode gives the sandbox its own netns, so ``127.0.0.1`` there is not the
host where rootlesskit's port driver listens. Tests dial the published host
port on ``127.0.0.1``. This relay binds that address inside the sandbox and
connects out through the port gateway (pasta's mapped host loopback, or
slirp's ``10.0.2.2``).
"""

from __future__ import annotations

import json
import logging
import socket
import subprocess
import threading

log = logging.getLogger(__name__)

PORT_GATEWAY_ENV = "BUDDELKISTE_HOST_PORT_GATEWAY"
DOCKER_HOST_ENV = "BUDDELKISTE_DOCKER_HOST"
PASTA_PORT_GATEWAY = "169.254.255.254"
SLIRP_PORT_GATEWAY = "10.0.2.2"


def sandbox_docker_host(bwrap_args: list[str]) -> str | None:
    """Return the last ``DOCKER_HOST`` ``--setenv`` value that is a Unix socket."""
    host: str | None = None
    index = 0
    while index + 2 < len(bwrap_args):
        if bwrap_args[index] == "--setenv" and bwrap_args[index + 1] == "DOCKER_HOST":
            host = bwrap_args[index + 2]
        index += 1
    if host and host.startswith("unix://"):
        return host
    return None


def published_tcp_ports(payload: bytes) -> set[int]:
    """Host TCP ports from a ``GET /containers/json`` body."""
    try:
        rows = json.loads(payload.decode("utf-8") or "[]")
    except json.JSONDecodeError:
        return set()
    if not isinstance(rows, list):
        return set()
    ports: set[int] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        for entry in row.get("Ports") or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("Type") not in (None, "tcp"):
                continue
            public = entry.get("PublicPort")
            if isinstance(public, int) and 0 < public < 65536:
                ports.add(public)
    return ports


def _http_get(sock_path: str, path: str, timeout: float = 2.0) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(sock_path)
        sock.sendall(
            f"GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n".encode()
        )
        chunks: list[bytes] = []
        while True:
            try:
                chunk = sock.recv(65536)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
    data = b"".join(chunks)
    _head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        return b""
    return body


def _nft_element(action: str, port: int) -> None:
    proc = subprocess.run(
        [
            "nft",
            action,
            "element",
            "inet",
            "buddelkiste",
            "fwd_ports",
            "{",
            str(port),
            "}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        log.debug("nft %s element %s: %s", action, port, detail)


def _copy(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class PublishedPortRelay:
    """Listen on sandbox ``127.0.0.1:<host-port>`` and dial the port gateway."""

    def __init__(self, docker_host: str, gateway: str) -> None:
        self.sock_path = docker_host.removeprefix("unix://")
        self.gateway = gateway
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._listeners: dict[int, socket.socket] = {}
        self._thread = threading.Thread(
            target=self._poll,
            name="buddelkiste-port-relay",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            listeners = list(self._listeners.items())
            self._listeners.clear()
        for port, srv in listeners:
            _nft_element("delete", port)
            try:
                srv.close()
            except OSError:
                pass
        self._thread.join(timeout=2)

    def _poll(self) -> None:
        while not self._stop.is_set():
            try:
                body = _http_get(self.sock_path, "/containers/json")
                self._sync(published_tcp_ports(body))
            except OSError as exc:
                log.debug("published-port poll failed: %s", exc)
            self._stop.wait(0.1)

    def _sync(self, ports: set[int]) -> None:
        with self._lock:
            current = set(self._listeners)
        for port in sorted(ports - current):
            self._open(port)
        for port in sorted(current - ports):
            self._close(port)

    def _open(self, port: int) -> None:
        _nft_element("add", port)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("127.0.0.1", port))
            srv.listen(16)
            srv.settimeout(0.5)
        except OSError as exc:
            srv.close()
            _nft_element("delete", port)
            log.debug("published-port bind %s failed: %s", port, exc)
            return
        with self._lock:
            self._listeners[port] = srv
        threading.Thread(
            target=self._accept,
            args=(port, srv),
            name=f"buddelkiste-port-{port}",
            daemon=True,
        ).start()

    def _close(self, port: int) -> None:
        with self._lock:
            srv = self._listeners.pop(port, None)
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass
        _nft_element("delete", port)

    def _accept(self, port: int, srv: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                client, _addr = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(
                target=self._handle,
                args=(client, port),
                daemon=True,
            ).start()

    def _handle(self, client: socket.socket, port: int) -> None:
        try:
            upstream = socket.create_connection((self.gateway, port), timeout=3)
        except OSError as exc:
            log.debug(
                "published-port gateway %s:%s failed: %s", self.gateway, port, exc
            )
            client.close()
            return
        left = threading.Thread(target=_copy, args=(client, upstream), daemon=True)
        right = threading.Thread(target=_copy, args=(upstream, client), daemon=True)
        left.start()
        right.start()
        left.join()
        right.join()
        client.close()
        upstream.close()
