from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import click
import pytest

from buddelkiste.network import (
    DENY_PRESETS,
    NetworkConfig,
    build_nft_ruleset,
    canonicalize_cidr,
    expand_deny_presets,
    format_deny_presets_help,
    load_deny_preset_registry,
    relay_debug_file,
    relay_debug_stream,
    resolv_conf_nameservers,
    resolve_network,
    run_bwrap,
    with_share_net,
)
from buddelkiste.published_ports import published_tcp_ports


def test_canonicalize_cidr_accepts_ip_and_prefix() -> None:
    assert canonicalize_cidr("1.2.3.4") == "1.2.3.4/32"
    assert canonicalize_cidr("10.0.0.0/8") == "10.0.0.0/8"
    assert canonicalize_cidr("2001:db8::1") == "2001:db8::1/128"


def test_canonicalize_cidr_rejects_hostname() -> None:
    with pytest.raises(click.ClickException, match="Invalid IP/CIDR"):
        canonicalize_cidr("example.com")


def test_resolve_network_accepts_hostnames() -> None:
    net = resolve_network(
        {
            "network": {
                "mode": "filter",
                "allow": ["1.1.1.1/32", "api.github.com", "*.pypi.org"],
                "deny": ["evil.example"],
            }
        }
    )
    assert net.allow == ["1.1.1.1/32"]
    assert net.allow_hosts == ["api.github.com", "*.pypi.org"]
    assert net.deny_hosts == ["evil.example"]
    assert net.needs_dns_proxy is True


def test_build_nft_ruleset_includes_dns_redirect_and_dyn_sets() -> None:
    net = NetworkConfig(mode="filter", policy="deny", allow=["1.1.1.1/32"])
    rules = build_nft_ruleset(net, dns_proxy=True)
    assert "dyn_allow4" in rules
    assert "dns_redirect" in rules
    assert "udp dport 53 redirect to :15353" in rules
    assert "tcp dport 53 redirect" not in rules
    assert "127.0.0.1/32" in rules


def test_resolve_network_defaults() -> None:
    net = resolve_network({})
    assert net.mode == "filter"
    assert net.backend == "pasta"
    assert net.policy == "allow"
    assert net.allow == []
    assert "10.0.0.0/8" in net.deny
    assert "127.0.0.0/8" in net.deny
    assert set(net.deny_presets) == {"internal", "localhost"}


def test_resolve_network_implies_filter_from_cli_options() -> None:
    assert resolve_network({}, allow=["1.1.1.1/32"]).mode == "filter"
    assert resolve_network({}, deny=["10.0.0.0/8"]).mode == "filter"
    assert resolve_network({}, deny_presets=["metadata"]).mode == "filter"
    assert resolve_network({}, allow_presets=["metadata"]).mode == "filter"
    assert resolve_network({}, policy="allow").mode == "filter"


def test_resolve_network_implies_filter_from_config_without_mode() -> None:
    net = resolve_network({"network": {"allow": ["1.1.1.1/32"]}})
    assert net.mode == "filter"
    assert net.allow == ["1.1.1.1/32"]

    presets = resolve_network({"network": {"deny_presets": ["private"]}})
    assert presets.mode == "filter"
    assert "10.0.0.0/8" in presets.deny

    allowed = resolve_network({"network": {"allow_presets": ["metadata"]}})
    assert allowed.mode == "filter"
    assert "169.254.169.254/32" in allowed.allow

    policy_only = resolve_network({"network": {"policy": "allow"}})
    assert policy_only.mode == "filter"
    assert policy_only.policy == "allow"


def test_resolve_network_backend_config_and_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BUDDELKISTE_NET_HELPER", raising=False)
    assert resolve_network({}).backend == "pasta"
    assert resolve_network({"network": {"backend": "slirp4netns"}}).backend == (
        "slirp4netns"
    )
    assert resolve_network({"network": {"backend": "slirp"}}).backend == "slirp4netns"
    assert resolve_network({}, backend="slirp4netns").backend == "slirp4netns"
    assert resolve_network(
        {"network": {"backend": "pasta"}},
        backend="slirp",
    ).backend == "slirp4netns"
    monkeypatch.setenv("BUDDELKISTE_NET_HELPER", "slirp4netns")
    assert resolve_network({}).backend == "slirp4netns"
    assert resolve_network({"network": {"backend": "pasta"}}).backend == "pasta"
    with pytest.raises(click.ClickException, match="network.backend"):
        resolve_network({"network": {"backend": "wireguard"}})
    with pytest.raises(click.ClickException, match="--net-backend"):
        resolve_network({}, backend="wireguard")


def test_resolve_network_explicit_mode_wins() -> None:
    assert resolve_network({}, mode="host", allow=["1.1.1.1/32"]).mode == "host"
    assert resolve_network({}, mode="none", deny_presets=["metadata"]).mode == "none"
    assert resolve_network(
        {"network": {"mode": "host", "allow": ["1.1.1.1/32"]}}
    ).mode == "host"
    # CLI filter flags still upgrade when config mode is host but --network omitted.
    assert resolve_network(
        {"network": {"mode": "host"}},
        allow=["1.1.1.1/32"],
    ).mode == "filter"


def test_deny_presets_expand() -> None:
    assert "10.0.0.0/8" in expand_deny_presets(["private"])
    assert expand_deny_presets(["internal"]) == expand_deny_presets(["private"])
    assert "127.0.0.0/8" in expand_deny_presets(["localhost"])
    assert "169.254.169.254/32" in expand_deny_presets(["metadata"])
    with pytest.raises(click.ClickException, match="Unknown network deny preset"):
        expand_deny_presets(["nope"])


def test_resolve_network_allow_presets() -> None:
    net = resolve_network(
        {
            "network": {
                "presets": {"corp": ["10.50.0.0/16", "vpn.example"]},
            }
        },
        allow_presets=["metadata", "corp"],
    )
    assert net.mode == "filter"
    assert "169.254.169.254/32" in net.allow
    assert "fd00:ec2::254/128" in net.allow
    assert "10.50.0.0/16" in net.allow
    assert "vpn.example" in net.allow_hosts
    assert set(net.allow_presets) == {"metadata", "corp"}
    with pytest.raises(click.ClickException, match="Unknown network allow preset"):
        resolve_network({}, allow_presets=["nope"])


def test_resolve_network_deny_presets() -> None:
    net = resolve_network(
        {"network": {"mode": "filter", "deny_presets": ["metadata", "linklocal"]}},
        deny_presets=["private"],
    )
    assert "169.254.169.254/32" in net.deny
    assert "169.254.0.0/16" in net.deny
    assert "10.0.0.0/8" in net.deny
    assert set(net.deny_presets) == {"metadata", "linklocal", "private"}


def test_format_deny_presets_help() -> None:
    text = format_deny_presets_help()
    for name in DENY_PRESETS:
        assert name in text


def test_custom_network_presets() -> None:
    config = {
        "network": {
            "mode": "filter",
            "deny_presets": ["corp", "metadata"],
            "presets": {
                "corp": ["10.50.0.0/16", "*.internal.example.com", "10.50.0.0/16"],
            },
        }
    }
    registry = load_deny_preset_registry(config)
    assert "corp" in registry
    assert registry["corp"] == ("10.50.0.0/16", "*.internal.example.com")
    assert " (custom)" in format_deny_presets_help(registry)

    net = resolve_network(config)
    assert "10.50.0.0/16" in net.deny
    assert "*.internal.example.com" in net.deny_hosts
    assert "169.254.169.254/32" in net.deny
    assert "corp" in net.deny_presets


def test_custom_network_presets_cli_append() -> None:
    net = resolve_network(
        {
            "network": {
                "presets": {"lab": ["203.0.113.0/24"]},
            }
        },
        deny_presets=["lab"],
    )
    assert "203.0.113.0/24" in net.deny


def test_custom_network_preset_rejects_builtin_name() -> None:
    with pytest.raises(click.ClickException, match="conflicts with built-in"):
        load_deny_preset_registry({"network": {"presets": {"private": ["1.1.1.1/32"]}}})


def test_custom_network_preset_rejects_bad_target() -> None:
    with pytest.raises(click.ClickException, match="Invalid IP/CIDR or hostname"):
        load_deny_preset_registry({"network": {"presets": {"bad": ["not a host!!"]}}})


def test_resolve_network_global_and_cli() -> None:
    net = resolve_network(
        {
            "network": {
                "mode": "filter",
                "policy": "deny",
                "allow": ["1.1.1.1/32"],
                "deny": ["169.254.169.254/32"],
            }
        },
        mode="filter",
        allow=["8.8.8.8"],
    )
    assert net.mode == "filter"
    assert "1.1.1.1/32" in net.allow
    assert "8.8.8.8/32" in net.allow
    assert "169.254.169.254/32" in net.deny


def test_resolve_network_per_executable() -> None:
    config = {
        "network": {"mode": "host"},
        "executables": {
            "curl": {
                "network": {
                    "mode": "filter",
                    "policy": "deny",
                    "allow": ["1.1.1.1/32"],
                }
            }
        },
    }
    host = resolve_network(config, executable=None)
    assert host.mode == "host"

    filtered = resolve_network(config, executable="/usr/bin/curl")
    assert filtered.mode == "filter"
    assert filtered.allow == ["1.1.1.1/32"]


def test_build_nft_ruleset_allowlist() -> None:
    net = NetworkConfig(
        mode="filter",
        policy="deny",
        allow=["1.1.1.1/32"],
        deny=["169.254.169.254/32"],
    )
    rules = build_nft_ruleset(net, extra_allow=["8.8.8.8/32"])
    assert "policy drop" in rules
    assert "1.1.1.1/32" in rules
    assert "8.8.8.8/32" in rules
    assert "169.254.169.254/32" in rules
    assert 'oifname "lo" accept' in rules
    punched = build_nft_ruleset(
        NetworkConfig(mode="filter", policy="allow", deny=["172.16.0.0/12"]),
        dns_allow=["172.16.0.1/32"],
    )
    chain = punched.split("chain output", 1)[1]
    assert chain.index("@dyn_allow4 accept") < chain.index("@deny4 reject")
    assert chain.index("dport 53 accept") < chain.index("@deny4 reject")
    assert "172.16.0.1/32" in punched


def test_build_nft_ruleset_punches_published_port_gateway() -> None:
    rules = build_nft_ruleset(
        NetworkConfig(mode="filter", policy="allow"),
        port_gateway="169.254.255.254",
    )
    chain = rules.split("chain output", 1)[1]
    assert "169.254.255.254/32" in rules
    assert chain.index("tcp dport @fwd_ports accept") < chain.index("@deny4 reject")

    slirp = build_nft_ruleset(
        NetworkConfig(mode="filter", policy="allow", deny=["10.0.0.0/8"]),
        port_gateway="10.0.2.2",
    )
    assert slirp.count("10.0.0.0/8") == 1
    assert "10.0.2.2/32" not in slirp
    assert "ip daddr 10.0.2.2 tcp dport @fwd_ports accept" in slirp


def test_build_nft_ruleset_denylist_policy_allow() -> None:
    net = NetworkConfig(mode="filter", policy="allow", deny=["10.0.0.0/8"])
    rules = build_nft_ruleset(net)
    assert "policy accept" in rules
    assert "10.0.0.0/8" in rules
    assert "@deny4 reject" in rules
    assert "\n    reject\n" not in rules


def test_build_nft_ruleset_collapses_overlapping_intervals() -> None:
    net = NetworkConfig(
        mode="filter",
        policy="deny",
        deny=["fc00::/7", "fd00:ec2::254/128", "127.0.0.0/8", "127.0.0.53/32"],
    )
    rules = build_nft_ruleset(net)
    assert "fc00::/7" in rules
    assert "fd00:ec2::254/128" not in rules
    assert "127.0.0.0/8" in rules
    assert "127.0.0.53/32" not in rules


def test_resolv_conf_nameservers(tmp_path: Path) -> None:
    resolv = tmp_path / "resolv.conf"
    resolv.write_text(
        "# comment\nnameserver 1.1.1.1\nnameserver 2001:db8::1\nsearch example\n",
        encoding="utf-8",
    )
    assert resolv_conf_nameservers(resolv) == ["1.1.1.1/32", "2001:db8::1/128"]


def test_with_share_net_inserts_after_unshare_all() -> None:
    assert with_share_net(["bwrap", "--unshare-all", "--clearenv", "--", "true"]) == [
        "bwrap",
        "--unshare-all",
        "--share-net",
        "--clearenv",
        "--",
        "true",
    ]


def test_run_bwrap_host_shares_net(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    captured: dict = {}

    def fake_run(args, check=False):
        captured["args"] = list(args)
        return MagicMock(returncode=7)

    monkeypatch.setattr("buddelkiste.network.subprocess.run", fake_run)
    with caplog.at_level(logging.DEBUG, logger="buddelkiste"):
        code = run_bwrap(["bwrap", "--unshare-all", "--", "true"], NetworkConfig(mode="host"))
    assert code == 7
    assert "--share-net" in captured["args"]
    assert "Running bwrap:" in caplog.text


def test_run_bwrap_none_no_share_net(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_run(args, check=False):
        captured["args"] = list(args)
        return MagicMock(returncode=0)

    monkeypatch.setattr("buddelkiste.network.subprocess.run", fake_run)
    run_bwrap(["bwrap", "--unshare-all", "--", "true"], NetworkConfig(mode="none"))
    assert "--share-net" not in captured["args"]


def test_run_bwrap_filter_requires_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BUDDELKISTE_NET_HELPER", raising=False)
    def which(name: str):
        return {
            "nft": "/usr/bin/nft",
            "setpriv": "/usr/bin/setpriv",
        }.get(name)

    monkeypatch.setattr("buddelkiste.network.which", which)
    with pytest.raises(click.ClickException, match="pasta"):
        run_bwrap(["bwrap", "--unshare-all", "--", "true"], NetworkConfig(mode="filter"))


def test_run_bwrap_filter_launches_pasta(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BUDDELKISTE_NET_HELPER", raising=False)
    monkeypatch.delenv("BUDDELKISTE_DEBUG", raising=False)
    def which(name: str):
        return {
            "nft": "/usr/bin/nft",
            "setpriv": "/usr/bin/setpriv",
            "pasta": "/usr/bin/pasta",
        }.get(name)

    captured: dict = {}

    def fake_run(args, check=False, **_kwargs):
        captured["args"] = list(args)
        return MagicMock(returncode=0)

    monkeypatch.setattr("buddelkiste.network.which", which)
    monkeypatch.setattr("buddelkiste.network.subprocess.run", fake_run)

    code = run_bwrap(
        ["bwrap", "--unshare-all", "--", "true"],
        NetworkConfig(mode="filter", policy="deny", allow=["1.1.1.1/32"]),
    )
    assert code == 0
    assert captured["args"][0] == "/usr/bin/pasta"
    assert "--ipv4-only" in captured["args"]
    assert captured["args"][captured["args"].index("--dns") + 1] == "none"
    assert captured["args"][captured["args"].index("--search") + 1] == "none"
    assert "--config-net" in captured["args"]
    assert "--map-host-loopback" in captured["args"]
    assert captured["args"][captured["args"].index("--map-host-loopback") + 1] == "none"
    assert captured["args"][captured["args"].index("--") + 1] == "/bin/sh"
    assert "--debug" not in captured["args"]
    assert "--log-file" not in captured["args"]
    assert captured["args"][captured["args"].index("-c") + 1] == 'exec "$@"'


def _pasta_which(name: str) -> str | None:
    return {
        "nft": "/usr/bin/nft",
        "setpriv": "/usr/bin/setpriv",
        "pasta": "/usr/bin/pasta",
    }.get(name)


def test_run_bwrap_filter_pasta_debug_tty(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("BUDDELKISTE_NET_HELPER", raising=False)
    monkeypatch.setenv("BUDDELKISTE_DEBUG", "1")
    monkeypatch.setattr("buddelkiste.network.sys.stderr.isatty", lambda: True)
    monkeypatch.setattr("buddelkiste.network.which", _pasta_which)
    captured: dict = {}

    def fake_popen(args, **kwargs):
        captured["args"] = list(args)
        captured["stderr"] = kwargs.get("stderr")
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, "rb")
        os.write(write_fd, b"pasta says hi\n")
        os.close(write_fd)
        proc = MagicMock()
        proc.stderr = stream
        proc.wait.return_value = 0
        return proc

    monkeypatch.setattr("buddelkiste.network.subprocess.Popen", fake_popen)
    with caplog.at_level(logging.DEBUG, logger="buddelkiste"):
        code = run_bwrap(
            ["bwrap", "--unshare-all", "--", "true"],
            NetworkConfig(mode="filter"),
        )
    assert code == 0
    assert "--debug" in captured["args"]
    assert "--log-file" not in captured["args"]
    assert captured["stderr"] is subprocess.PIPE
    assert captured["args"][captured["args"].index("-c") + 1] == 'exec 2>/dev/tty; exec "$@"'
    assert "Running pasta:" in caplog.text
    assert "pasta: pasta says hi" in caplog.text


def test_run_bwrap_filter_pasta_debug_log_file(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("BUDDELKISTE_NET_HELPER", raising=False)
    monkeypatch.setenv("BUDDELKISTE_DEBUG", "1")
    monkeypatch.setattr("buddelkiste.network.sys.stderr.isatty", lambda: False)
    monkeypatch.setattr("buddelkiste.network.which", _pasta_which)
    captured: dict = {}

    def fake_run(args, check=False, **_kwargs):
        captured["args"] = list(args)
        return MagicMock(returncode=0)

    monkeypatch.setattr("buddelkiste.network.subprocess.run", fake_run)
    with caplog.at_level(logging.DEBUG, logger="buddelkiste"):
        code = run_bwrap(
            ["bwrap", "--unshare-all", "--", "true"],
            NetworkConfig(mode="filter"),
        )
    assert code == 0
    assert "--debug" in captured["args"]
    log_file = captured["args"][captured["args"].index("--log-file") + 1]
    assert log_file.endswith("/pasta.log")
    assert captured["args"][captured["args"].index("-c") + 1] == 'exec "$@"'
    assert "Running pasta:" in caplog.text


def _relay_pipe(label: str, payload: bytes) -> threading.Thread:
    read_fd, write_fd = os.pipe()
    stream = os.fdopen(read_fd, "rb")
    try:
        os.write(write_fd, payload)
    finally:
        os.close(write_fd)
    return relay_debug_stream(stream, label)


def test_relay_debug_stream_prefixes_lines(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger="buddelkiste"):
        pasta = _relay_pipe("pasta", b"from-pasta\n")
        slirp = _relay_pipe("slirp4netns", b"tap ready\n")
        pasta.join(timeout=2)
        slirp.join(timeout=2)
    assert pasta.is_alive() is False
    assert slirp.is_alive() is False
    assert "pasta: from-pasta" in caplog.text
    assert "slirp4netns: tap ready" in caplog.text


def test_relay_debug_file_prefixes_lines(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "pasta.log"
    path.write_bytes(b"route picked\n")
    stop = threading.Event()
    with caplog.at_level(logging.DEBUG, logger="buddelkiste"):
        thread = relay_debug_file(path, "pasta", stop)
        deadline = time.monotonic() + 1
        while "pasta: route picked" not in caplog.text and time.monotonic() < deadline:
            time.sleep(0.02)
        stop.set()
        thread.join(timeout=2)
    assert "pasta: route picked" in caplog.text
    assert thread.is_alive() is False


def test_run_bwrap_filter_maps_host_loopback_for_docker_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BUDDELKISTE_NET_HELPER", raising=False)
    monkeypatch.delenv("BUDDELKISTE_DEBUG", raising=False)

    def which(name: str):
        return {
            "nft": "/usr/bin/nft",
            "setpriv": "/usr/bin/setpriv",
            "pasta": "/usr/bin/pasta",
        }.get(name)

    captured: dict = {}

    def fake_run(args, check=False, **kwargs):
        captured["args"] = list(args)
        captured["env"] = kwargs.get("env") or {}
        return MagicMock(returncode=0)

    monkeypatch.setattr("buddelkiste.network.which", which)
    monkeypatch.setattr("buddelkiste.network.subprocess.run", fake_run)

    code = run_bwrap(
        [
            "bwrap",
            "--unshare-all",
            "--setenv",
            "DOCKER_HOST",
            "unix:///run/user/1000/bdi1/bk-dp-1.sock",
            "--",
            "true",
        ],
        NetworkConfig(mode="filter"),
    )
    assert code == 0
    gateway = captured["args"][captured["args"].index("--map-host-loopback") + 1]
    assert gateway == "169.254.255.254"
    assert captured["env"]["BUDDELKISTE_HOST_PORT_GATEWAY"] == gateway
    assert captured["env"]["BUDDELKISTE_DOCKER_HOST"].endswith("bk-dp-1.sock")
    assert "buddelkiste.network_inner" in captured["args"]


def test_published_tcp_ports_reads_host_bindings() -> None:
    body = (
        b'[{"Ports":[{"IP":"0.0.0.0","PrivatePort":22,"PublicPort":32768,"Type":"tcp"},'
        b'{"IP":"::","PrivatePort":22,"PublicPort":32768,"Type":"tcp"},'
        b'{"PrivatePort":22,"Type":"tcp"}]}]'
    )
    assert published_tcp_ports(body) == {32768}
    assert published_tcp_ports(b"not-json") == set()
