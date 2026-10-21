"""Unit tests for the sandbox published-port relay."""

from __future__ import annotations

import json
import logging
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

from buddelkiste import published_ports as pp


def _wait_until(predicate, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition not met")


def _bind_ephemeral() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    return sock


def _read_http_request(conn: socket.socket) -> bytes:
    conn.settimeout(2)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def _serve_unix(path: Path, handler) -> threading.Thread:
    ready = threading.Event()

    def run() -> None:
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(path))
        srv.listen(1)
        ready.set()
        conn, _addr = srv.accept()
        try:
            handler(conn)
        finally:
            conn.close()
            srv.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert ready.wait(2)
    return thread


def test_sandbox_docker_host_uses_last_unix_socket() -> None:
    assert pp.sandbox_docker_host([]) is None
    assert pp.sandbox_docker_host(["--setenv", "DOCKER_HOST"]) is None
    assert pp.sandbox_docker_host(["--setenv", "PATH", "/bin"]) is None
    assert pp.sandbox_docker_host(["--setenv", "DOCKER_HOST", ""]) is None
    assert pp.sandbox_docker_host(["--setenv", "DOCKER_HOST", "tcp://1.2.3.4"]) is None
    assert (
        pp.sandbox_docker_host(
            [
                "--setenv",
                "DOCKER_HOST",
                "unix:///first.sock",
                "--setenv",
                "DOCKER_HOST",
                "tcp://1.2.3.4",
            ]
        )
        is None
    )
    assert (
        pp.sandbox_docker_host(
            [
                "--setenv",
                "DOCKER_HOST",
                "unix:///first.sock",
                "--unshare-net",
                "--setenv",
                "DOCKER_HOST",
                "unix:///last.sock",
            ]
        )
        == "unix:///last.sock"
    )


def test_published_tcp_ports_filters_unusable_rows() -> None:
    assert pp.published_tcp_ports(b"") == set()
    assert pp.published_tcp_ports(b"not-json") == set()
    assert pp.published_tcp_ports(b"null") == set()
    assert pp.published_tcp_ports(b"{}") == set()
    assert pp.published_tcp_ports(b"[1, null]") == set()
    assert pp.published_tcp_ports(b'[{"Ports": null}, {"Ports": []}]') == set()
    assert pp.published_tcp_ports(b'[{"Ports": [null, "x"]}]') == set()
    body = json.dumps(
        [
            {
                "Ports": [
                    {"Type": "udp", "PublicPort": 53},
                    {"Type": "TCP", "PublicPort": 1},
                    {"PublicPort": 22},
                    {"Type": "tcp", "PublicPort": 0},
                    {"Type": "tcp", "PublicPort": -5},
                    {"Type": "tcp", "PublicPort": 65536},
                    {"Type": "tcp", "PublicPort": "80"},
                    {"Type": "tcp", "PublicPort": 8080},
                    {"Type": None, "PublicPort": 9},
                ]
            }
        ]
    ).encode()
    assert pp.published_tcp_ports(body) == {9, 22, 8080}


def test_http_get_returns_response_body(tmp_path: Path) -> None:
    path = tmp_path / "d.sock"
    seen: dict[str, bytes] = {}

    def handler(conn: socket.socket) -> None:
        seen["req"] = _read_http_request(conn)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n")
        conn.sendall(b'[{"ok":true}]')

    thread = _serve_unix(path, handler)
    body = pp._http_get(str(path), "/containers/json", timeout=2)
    thread.join(timeout=2)
    assert b"GET /containers/json HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n" in seen[
        "req"
    ]
    assert body == b'[{"ok":true}]'


def test_http_get_returns_empty_without_header_separator(tmp_path: Path) -> None:
    path = tmp_path / "d.sock"

    def handler(conn: socket.socket) -> None:
        _read_http_request(conn)
        conn.sendall(b"not-http")

    thread = _serve_unix(path, handler)
    assert pp._http_get(str(path), "/containers/json") == b""
    thread.join(timeout=2)


def test_http_get_returns_empty_on_read_timeout(tmp_path: Path) -> None:
    path = tmp_path / "d.sock"

    def handler(conn: socket.socket) -> None:
        _read_http_request(conn)
        time.sleep(0.5)

    thread = _serve_unix(path, handler)
    started = time.monotonic()
    assert pp._http_get(str(path), "/containers/json", timeout=0.1) == b""
    assert time.monotonic() - started < 1
    thread.join(timeout=2)


def test_nft_element_invokes_nft_and_logs_failures(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    calls: list[list[str]] = []
    results = [
        subprocess.CompletedProcess([], 0, "", ""),
        subprocess.CompletedProcess([], 1, "", "no such table"),
        subprocess.CompletedProcess([], 2, "from-stdout", ""),
    ]

    def fake_run(args, check=False, capture_output=True, text=True):
        calls.append(list(args))
        assert check is False
        assert capture_output is True
        assert text is True
        return results.pop(0)

    monkeypatch.setattr(pp.subprocess, "run", fake_run)
    with caplog.at_level(logging.DEBUG):
        pp._nft_element("add", 8080)
        pp._nft_element("delete", 1)
        pp._nft_element("add", 2)
    assert calls[0] == [
        "nft",
        "add",
        "element",
        "inet",
        "buddelkiste",
        "fwd_ports",
        "{",
        "8080",
        "}",
    ]
    assert "no such table" in caplog.text
    assert "from-stdout" in caplog.text
    assert "delete element 1" in caplog.text


def test_copy_forwards_until_eof() -> None:
    src_w, src_r = socket.socketpair()
    dst_r, dst_w = socket.socketpair()
    worker = threading.Thread(target=pp._copy, args=(src_r, dst_w), daemon=True)
    worker.start()
    try:
        src_w.sendall(b"abc")
        src_w.shutdown(socket.SHUT_WR)
        dst_r.settimeout(2)
        assert dst_r.recv(16) == b"abc"
        assert dst_r.recv(16) == b""
        worker.join(timeout=2)
        assert not worker.is_alive()
    finally:
        for sock in (src_w, src_r, dst_r, dst_w):
            sock.close()


def test_copy_swallows_socket_errors() -> None:
    class _Src:
        def recv(self, _n: int) -> bytes:
            raise OSError("reset")

    class _Dst:
        def shutdown(self, _how: int) -> None:
            raise OSError("shut")

    pp._copy(_Src(), _Dst())  # type: ignore[arg-type]


def test_open_reverts_nft_when_bind_fails(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    holder = _bind_ephemeral()
    holder.listen(1)
    port = holder.getsockname()[1]
    nft: list[tuple[str, int]] = []
    monkeypatch.setattr(pp, "_nft_element", lambda action, bound: nft.append((action, bound)))
    relay = pp.PublishedPortRelay("unix:///run/docker.sock", pp.SLIRP_PORT_GATEWAY)
    try:
        with caplog.at_level(logging.DEBUG):
            relay._open(port)
        assert port not in relay._listeners
        assert nft == [("add", port), ("delete", port)]
        assert f"bind {port} failed" in caplog.text
    finally:
        holder.close()


def test_close_missing_port_still_drops_nft(monkeypatch: pytest.MonkeyPatch) -> None:
    nft: list[tuple[str, int]] = []
    monkeypatch.setattr(pp, "_nft_element", lambda action, port: nft.append((action, port)))
    relay = pp.PublishedPortRelay("/var/run/docker.sock", pp.PASTA_PORT_GATEWAY)
    assert relay.sock_path == "/var/run/docker.sock"
    relay._close(9)
    assert nft == [("delete", 9)]
    assert relay._listeners == {}


def test_close_swallows_socket_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom:
        def close(self) -> None:
            raise OSError("boom")

    monkeypatch.setattr(pp, "_nft_element", lambda *_args: None)
    relay = pp.PublishedPortRelay("unix:///run/docker.sock", pp.SLIRP_PORT_GATEWAY)
    assert relay.sock_path == "/run/docker.sock"
    relay._listeners[4] = _Boom()  # type: ignore[assignment]
    relay._close(4)
    assert 4 not in relay._listeners


def test_accept_ignores_timeouts_until_stop() -> None:
    srv = _bind_ephemeral()
    srv.listen(1)
    srv.settimeout(0.01)
    relay = pp.PublishedPortRelay("unix:///run/docker.sock", pp.SLIRP_PORT_GATEWAY)

    def stop_soon() -> None:
        time.sleep(0.05)
        relay._stop.set()

    threading.Thread(target=stop_soon, daemon=True).start()
    try:
        relay._accept(srv.getsockname()[1], srv)
    finally:
        srv.close()


def test_accept_returns_when_listener_closes() -> None:
    srv = _bind_ephemeral()
    srv.listen(1)
    srv.settimeout(2)
    relay = pp.PublishedPortRelay("unix:///run/docker.sock", pp.SLIRP_PORT_GATEWAY)

    def close_soon() -> None:
        time.sleep(0.05)
        srv.close()

    threading.Thread(target=close_soon, daemon=True).start()
    relay._accept(1, srv)


def test_poll_logs_socket_errors(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    relay = pp.PublishedPortRelay("unix:///run/docker.sock", pp.PASTA_PORT_GATEWAY)

    def boom(_sock_path: str, _path: str, timeout: float = 2.0) -> bytes:
        assert timeout == 2.0
        relay._stop.set()
        raise OSError("down")

    monkeypatch.setattr(pp, "_http_get", boom)
    with caplog.at_level(logging.DEBUG):
        relay._poll()
    assert "published-port poll failed: down" in caplog.text


def test_start_stop_without_published_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pp, "_http_get", lambda *_args, **_kwargs: b"[]")
    monkeypatch.setattr(pp, "_nft_element", lambda *_args: None)
    relay = pp.PublishedPortRelay("unix:///run/docker.sock", pp.PASTA_PORT_GATEWAY)
    relay.start()
    relay.stop()
    assert not relay._thread.is_alive()


def test_stop_closes_listeners_and_ignores_close_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Idle(pp.PublishedPortRelay):
        def _poll(self) -> None:
            self._stop.wait()

    class _Boom:
        def close(self) -> None:
            raise OSError("boom")

    closed: list[str] = []

    class _Tracked(socket.socket):
        def close(self) -> None:
            closed.append("ok")
            super().close()

    monkeypatch.setattr(pp, "_nft_element", lambda *_args: None)
    relay = _Idle("unix:///run/docker.sock", pp.SLIRP_PORT_GATEWAY)
    live = _Tracked()
    live.bind(("127.0.0.1", 0))
    live.listen(1)
    relay._listeners[live.getsockname()[1]] = live
    relay._listeners[2] = _Boom()  # type: ignore[assignment]
    relay.start()
    try:
        relay.stop()
    finally:
        if live.fileno() != -1:
            live.close()
    assert closed == ["ok"]
    assert relay._listeners == {}
    assert not relay._thread.is_alive()


def test_relay_forwards_published_port_then_drops_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relay_holder = _bind_ephemeral()
    upstream = _bind_ephemeral()
    published_port = relay_holder.getsockname()[1]
    upstream_port = upstream.getsockname()[1]
    relay_holder.close()
    upstream.listen(1)
    upstream.settimeout(2)

    received: dict[str, bytes] = {}

    def accept_upstream() -> None:
        conn, _addr = upstream.accept()
        try:
            conn.settimeout(2)
            received["ping"] = conn.recv(4)
            conn.sendall(b"pong")
            conn.shutdown(socket.SHUT_WR)
            try:
                conn.recv(16)
            except OSError:
                pass
        finally:
            conn.close()

    accept_thread = threading.Thread(target=accept_upstream, daemon=True)
    accept_thread.start()

    nft: list[tuple[str, int]] = []
    monkeypatch.setattr(pp, "_nft_element", lambda action, port: nft.append((action, port)))
    state: dict[str, set[int]] = {"ports": {published_port}}

    def fake_http(_sock_path: str, path: str, timeout: float = 2.0) -> bytes:
        assert path == "/containers/json"
        assert timeout == 2.0
        rows = [
            {"Ports": [{"Type": "tcp", "PublicPort": port}]} for port in sorted(state["ports"])
        ]
        return json.dumps(rows).encode()

    monkeypatch.setattr(pp, "_http_get", fake_http)
    real_create = socket.create_connection

    def fake_create(addr, timeout=None):
        host, port = addr
        if host == pp.PASTA_PORT_GATEWAY:
            assert port == published_port
            return real_create(("127.0.0.1", upstream_port), timeout)
        return real_create(addr, timeout)

    monkeypatch.setattr(pp.socket, "create_connection", fake_create)

    relay = pp.PublishedPortRelay("unix:///run/docker.sock", pp.PASTA_PORT_GATEWAY)
    relay.start()
    client: socket.socket | None = None
    try:
        _wait_until(lambda: published_port in relay._listeners)
        client = real_create(("127.0.0.1", published_port), timeout=2)
        client.settimeout(2)
        client.sendall(b"ping")
        assert client.recv(4) == b"pong"
        client.close()
        client = None
        accept_thread.join(timeout=2)
        assert not accept_thread.is_alive()
        assert received["ping"] == b"ping"
        assert ("add", published_port) in nft

        state["ports"] = set()
        _wait_until(
            lambda: published_port not in relay._listeners and ("delete", published_port) in nft
        )
    finally:
        if client is not None:
            client.close()
        relay.stop()
        upstream.close()
        accept_thread.join(timeout=2)


def test_relay_closes_client_when_gateway_connect_fails(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    holder = _bind_ephemeral()
    port = holder.getsockname()[1]
    holder.close()
    monkeypatch.setattr(pp, "_nft_element", lambda *_args: None)
    real_create = socket.create_connection

    def fail_gateway(addr, timeout=None):
        raise OSError("refused")

    monkeypatch.setattr(pp.socket, "create_connection", fail_gateway)
    body = json.dumps([{"Ports": [{"Type": "tcp", "PublicPort": port}]}]).encode()
    monkeypatch.setattr(pp, "_http_get", lambda *_args, **_kwargs: body)
    relay = pp.PublishedPortRelay("unix:///run/docker.sock", pp.SLIRP_PORT_GATEWAY)
    relay.start()
    client: socket.socket | None = None
    try:
        _wait_until(lambda: port in relay._listeners)
        client = real_create(("127.0.0.1", port), timeout=2)
        client.settimeout(2)
        with caplog.at_level(logging.DEBUG):
            assert client.recv(16) == b""
        assert "refused" in caplog.text
    finally:
        if client is not None:
            client.close()
        relay.stop()
