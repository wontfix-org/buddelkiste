"""Selective network isolation for the sandbox.

Modes:
  host   — share the host network (default; current behavior)
  none   — private empty netns (no connectivity)
  filter — private netns via pasta/slirp4netns with in-namespace nftables.
           Default policy is allow (public egress). Private ranges and
           loopback are denied.

Filter mode needs no root and no host IP/subnet reservation. Rules accept
IP/CIDR literals and hostnames (exact or ``*.suffix``). Hostnames are enforced
via a DNS proxy that publishes resolved A/AAAA addresses into dynamic nft sets.
DNS resolver addresses from /etc/resolv.conf are auto-allowed.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import select
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import click

from buddelkiste.dns_proxy import (
    DNS_PROXY_PORT,
    DnsProxy,
    HostDnsRelay,
    is_valid_hostname_pattern,
    nft_add_allow_ip,
)
from buddelkiste.features import lookup_executable_config
from buddelkiste.published_ports import (
    DOCKER_HOST_ENV,
    PASTA_PORT_GATEWAY,
    PORT_GATEWAY_ENV,
    SLIRP_PORT_GATEWAY,
    PublishedPortRelay,
    sandbox_docker_host,
)
from buddelkiste.which import path_with_tools, which

log = logging.getLogger(__name__)

NETWORK_MODES = ("host", "none", "filter")
NETWORK_POLICIES = ("allow", "deny")

# Named deny helpers expanded into concrete CIDRs at resolve time.
_PRIVATE_CIDRS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
)
DENY_PRESETS: dict[str, tuple[str, ...]] = {
    "private": _PRIVATE_CIDRS,
    # Alias for RFC1918/ULA — same ranges as ``private``.
    "internal": _PRIVATE_CIDRS,
    "localhost": (
        "127.0.0.0/8",
        "::1/128",
    ),
    "linklocal": (
        "169.254.0.0/16",
        "fe80::/10",
    ),
    "metadata": (
        "169.254.169.254/32",
        "fd00:ec2::254/128",
    ),
}

# Default filter deny list: internal (RFC1918/ULA) and loopback.
DEFAULT_DENY_PRESETS: tuple[str, ...] = ("internal", "localhost")


@dataclass
class NetworkConfig:
    mode: str = "filter"
    policy: str = "allow"
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    allow_presets: list[str] = field(default_factory=list)
    deny_presets: list[str] = field(
        default_factory=lambda: list(DEFAULT_DENY_PRESETS)
    )
    allow_hosts: list[str] = field(default_factory=list)
    deny_hosts: list[str] = field(default_factory=list)

    def normalized(
        self, registry: dict[str, tuple[str, ...]] | None = None
    ) -> NetworkConfig:
        presets_registry = registry if registry is not None else DENY_PRESETS
        allow_presets = validate_deny_presets(
            self.allow_presets, registry=presets_registry, kind="allow"
        )
        deny_presets = validate_deny_presets(
            self.deny_presets, registry=presets_registry, kind="deny"
        )
        allow_cidrs, allow_hosts = split_targets(
            [
                *self.allow,
                *expand_deny_presets(
                    allow_presets, registry=presets_registry, kind="allow"
                ),
            ]
        )
        deny_cidrs, deny_hosts = split_targets(
            [
                *self.deny,
                *expand_deny_presets(
                    deny_presets, registry=presets_registry, kind="deny"
                ),
            ]
        )
        allow_hosts = list(dict.fromkeys([*allow_hosts, *self.allow_hosts]))
        deny_hosts = list(dict.fromkeys([*deny_hosts, *self.deny_hosts]))
        return NetworkConfig(
            mode=self.mode,
            policy=self.policy,
            allow=allow_cidrs,
            deny=deny_cidrs,
            allow_presets=allow_presets,
            deny_presets=deny_presets,
            allow_hosts=allow_hosts,
            deny_hosts=deny_hosts,
        )

    @property
    def needs_dns_proxy(self) -> bool:
        return bool(self.allow_hosts or self.deny_hosts)


def load_deny_preset_registry(config: dict) -> dict[str, tuple[str, ...]]:
    """Built-in deny presets plus optional ``[network.presets]`` from config."""
    registry: dict[str, tuple[str, ...]] = dict(DENY_PRESETS)
    network = config.get("network")
    if network is None:
        return registry
    if not isinstance(network, dict):
        raise click.ClickException("Invalid network in config: expected a table")

    custom = network.get("presets")
    if custom is None:
        return registry
    if not isinstance(custom, dict):
        raise click.ClickException(
            "network.presets must be a table of name = [IP/CIDR or hostname, ...]"
        )

    for name, entries in custom.items():
        key = str(name)
        if key in DENY_PRESETS:
            raise click.ClickException(
                f"network.presets.{key} conflicts with built-in preset {key!r}"
            )
        if not isinstance(entries, list):
            raise click.ClickException(
                f"network.presets.{key} must be a list of IP/CIDR or hostname strings"
            )
        targets: list[str] = []
        for entry in entries:
            _kind, value = classify_target(str(entry))
            if value not in targets:
                targets.append(value)
        registry[key] = tuple(targets)
    return registry


def validate_deny_presets(
    presets: Sequence[str],
    *,
    registry: dict[str, tuple[str, ...]] | None = None,
    kind: str = "deny",
) -> list[str]:
    presets_registry = registry if registry is not None else DENY_PRESETS
    result: list[str] = []
    for name in presets:
        if name not in presets_registry:
            known = ", ".join(presets_registry)
            raise click.ClickException(
                f"Unknown network {kind} preset: {name!r} (expected {known})"
            )
        if name not in result:
            result.append(name)
    return result


def expand_deny_presets(
    presets: Sequence[str],
    *,
    registry: dict[str, tuple[str, ...]] | None = None,
    kind: str = "deny",
) -> list[str]:
    presets_registry = registry if registry is not None else DENY_PRESETS
    targets: list[str] = []
    for name in validate_deny_presets(presets, registry=presets_registry, kind=kind):
        targets.extend(presets_registry[name])
    return targets


def format_deny_presets_help(
    registry: dict[str, tuple[str, ...]] | None = None,
) -> str:
    presets_registry = registry if registry is not None else DENY_PRESETS
    lines = [
        "Available network presets (for --net-allow-preset or --net-deny-preset):",
        "",
    ]
    for name, targets in presets_registry.items():
        suffix = "" if name in DENY_PRESETS else " (custom)"
        body = ", ".join(targets) if targets else "(empty)"
        lines.append(f"  {name:10} {body}{suffix}")
    return "\n".join(lines)


def canonicalize_cidr(value: str) -> str:
    """Validate and normalize an IP or CIDR string."""
    text = value.strip()
    try:
        if "/" in text:
            return str(ipaddress.ip_network(text, strict=False))
        return str(ipaddress.ip_network(f"{text}/{32 if ':' not in text else 128}", strict=False))
    except ValueError as exc:
        raise click.ClickException(f"Invalid IP/CIDR: {value}") from exc


def classify_target(value: str) -> tuple[str, str]:
    """Return ``("cidr", cidr)`` or ``("host", hostname)`` for a rule entry."""
    text = value.strip()
    try:
        return "cidr", canonicalize_cidr(text)
    except click.ClickException:
        pass
    if is_valid_hostname_pattern(text):
        return "host", text.lower().rstrip(".")
    raise click.ClickException(f"Invalid IP/CIDR or hostname: {value}")


def split_targets(entries: Sequence[str]) -> tuple[list[str], list[str]]:
    cidrs: list[str] = []
    hosts: list[str] = []
    for entry in entries:
        kind, value = classify_target(entry)
        if kind == "cidr":
            if value not in cidrs:
                cidrs.append(value)
        elif value not in hosts:
            hosts.append(value)
    return cidrs, hosts


def parse_network_table(
    data: dict,
    *,
    where: str,
    registry: dict[str, tuple[str, ...]] | None = None,
) -> NetworkConfig:
    if not isinstance(data, dict):
        raise click.ClickException(f"Invalid network {where}: expected a table")

    mode = data.get("mode", "filter")
    if mode not in NETWORK_MODES:
        raise click.ClickException(
            f"Invalid network.mode {where}: {mode!r} (expected {', '.join(NETWORK_MODES)})"
        )

    policy = data.get("policy", "allow")
    if policy not in NETWORK_POLICIES:
        raise click.ClickException(
            f"Invalid network.policy {where}: {policy!r} "
            f"(expected {', '.join(NETWORK_POLICIES)})"
        )

    allow = data.get("allow", [])
    deny = data.get("deny", [])
    allow_presets = data.get("allow_presets", [])
    if "deny_presets" in data:
        deny_presets = data["deny_presets"]
    else:
        deny_presets = list(DEFAULT_DENY_PRESETS)
    if not isinstance(allow, list) or not isinstance(deny, list):
        raise click.ClickException(
            f"network.allow/deny {where} must be lists of IP/CIDR or hostname strings"
        )
    if not isinstance(allow_presets, list):
        raise click.ClickException(
            f"network.allow_presets {where} must be a list of preset names"
        )
    if not isinstance(deny_presets, list):
        raise click.ClickException(f"network.deny_presets {where} must be a list of preset names")

    cfg = NetworkConfig(
        mode=mode,
        policy=policy,
        allow=[str(x) for x in allow],
        deny=[str(x) for x in deny],
        allow_presets=[str(x) for x in allow_presets],
        deny_presets=[str(x) for x in deny_presets],
    )
    return cfg.normalized(registry)


def _effective_network_table(config: dict, executable: str | None) -> dict | None:
    exec_cfg = lookup_executable_config(config, executable)
    if exec_cfg is not None and isinstance(exec_cfg.get("network"), dict):
        return exec_cfg["network"]
    network = config.get("network")
    return network if isinstance(network, dict) else None


def _config_requests_filter(network: dict | None) -> bool:
    """True when a config network table uses filtering knobs."""
    if not network:
        return False
    if (
        network.get("allow")
        or network.get("deny")
        or network.get("allow_presets")
        or network.get("deny_presets")
    ):
        return True
    return "policy" in network


def resolve_network(
    config: dict,
    *,
    executable: str | None = None,
    mode: str | None = None,
    policy: str | None = None,
    allow: Sequence[str] = (),
    deny: Sequence[str] = (),
    allow_presets: Sequence[str] = (),
    deny_presets: Sequence[str] = (),
) -> NetworkConfig:
    """Resolve network settings.

    Precedence: defaults → global [network] → per-executable network → CLI flags.
    CLI ``--net-allow`` / ``--net-deny`` / ``--net-allow-preset`` /
    ``--net-deny-preset`` append to the lists; ``--network`` / ``--net-policy``
    override mode/policy when given.

    Filter mode is selected automatically when filtering options are used, unless
    ``--network`` (or an explicit config ``mode``) chooses another mode.

    Custom named presets may be defined under ``[network.presets]`` as
    ``name = ["IP/CIDR or hostname", ...]`` and referenced from either
    allow_presets or deny_presets.
    """
    registry = load_deny_preset_registry(config)
    network_table = _effective_network_table(config, executable)
    mode_from_config = bool(network_table and "mode" in network_table)
    net = NetworkConfig()
    if "network" in config:
        net = parse_network_table(config["network"], where="in config", registry=registry)

    exec_cfg = lookup_executable_config(config, executable)
    if exec_cfg is not None and "network" in exec_cfg:
        net = parse_network_table(
            exec_cfg["network"],
            where=f"for executable {executable!r}",
            registry=registry,
        )

    if mode is not None:
        if mode not in NETWORK_MODES:
            raise click.ClickException(
                f"Invalid --network mode: {mode!r} (expected {', '.join(NETWORK_MODES)})"
            )
        net.mode = mode

    if policy is not None:
        if policy not in NETWORK_POLICIES:
            raise click.ClickException(
                f"Invalid --net-policy: {policy!r} "
                f"(expected {', '.join(NETWORK_POLICIES)})"
            )
        net.policy = policy

    if allow:
        net.allow.extend(allow)
    if deny:
        net.deny.extend(deny)
    if allow_presets:
        net.allow_presets.extend(allow_presets)
    if deny_presets:
        net.deny_presets.extend(deny_presets)

    cli_filter = bool(
        policy is not None or allow or deny or allow_presets or deny_presets
    )
    if mode is None and (
        cli_filter or (not mode_from_config and _config_requests_filter(network_table))
    ):
        net.mode = "filter"

    return net.normalized(registry)


def resolv_conf_nameservers(path: Path | None = None) -> list[str]:
    """Return nameserver IPs from resolv.conf as /32 or /128 CIDRs."""
    resolv = path or Path("/etc/resolv.conf")
    try:
        lines = resolv.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        log.warning("failed to read %s: %s", resolv, exc)
        return []

    result: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            try:
                result.append(canonicalize_cidr(parts[1]))
            except click.ClickException:
                log.debug("ignoring invalid nameserver entry in %s: %s", resolv, parts[1])
                continue
    return result


# Loopback stubs such as systemd-resolved's 127.0.0.53 are not dialed from
# the sandbox. start_host_dns_relay forwards to the stub from the host netns.
def _nameserver_ips_from(path: Path) -> list[str]:
    ips: list[str] = []
    for cidr in resolv_conf_nameservers(path):
        net = ipaddress.ip_network(cidr, strict=False)
        if net.version == 4 and net.prefixlen == 32 or net.version == 6 and net.prefixlen == 128:
            addr = net.network_address
            # Loopback stubs are reached via the host-netns relay, not from here.
            if addr.is_loopback:
                continue
            ips.append(str(addr))
    return ips


def sandbox_nameservers(path: Path | None = None) -> list[str]:
    """Non-loopback nameservers in the resolv.conf the sandbox inherits.

    glibc reads ``/etc/resolv.conf`` only. A stub entry (``127.0.0.53``) means
    the sandbox has no usable resolver until queries are relayed to that stub
    from the host netns.
    """
    return _nameserver_ips_from(path or Path("/etc/resolv.conf"))


def nameserver_ips(
    path: Path | None = None,
    *,
    sources: Sequence[Path] | None = None,
) -> list[str]:
    """Bare nameserver addresses for DNS upstream forwarding.

    With no path, read /etc/resolv.conf only. Loopback stubs are omitted: those
    are reached through :func:`start_host_dns_relay`, not by dialing every
    uplink systemd-resolved would ask.
    """
    if path is not None:
        return _nameserver_ips_from(path)
    paths = list(sources) if sources is not None else [Path("/etc/resolv.conf")]
    ips: list[str] = []
    for source in paths:
        for ip in _nameserver_ips_from(source):
            if ip not in ips:
                ips.append(ip)
    return ips


def stub_nameserver(path: Path | None = None) -> str | None:
    """Loopback stub in resolv.conf when that file lists no other nameserver.

    ``None`` when a reachable nameserver is configured, or when the file has
    no nameservers at all.
    """
    loopback: str | None = None
    for cidr in resolv_conf_nameservers(path):
        net = ipaddress.ip_network(cidr, strict=False)
        host_route = (net.version == 4 and net.prefixlen == 32) or (
            net.version == 6 and net.prefixlen == 128
        )
        if not host_route:
            continue
        if not net.network_address.is_loopback:
            return None
        if loopback is None:
            loopback = str(net.network_address)
    return loopback


# Passed to the filter child: Unix socket of a relay running in the host netns.
DNS_RELAY_ENV = "BUDDELKISTE_DNS_RELAY"


def start_host_dns_relay(directory: Path) -> HostDnsRelay | None:
    """Relay sandbox DNS to the host stub resolver, when resolv.conf is one.

    The listener stays in this process, which is still in the host netns, so
    it can dial ``127.0.0.53``. The guest only sees the socket path.
    """
    stub = stub_nameserver()
    if stub is None:
        return None
    relay = HostDnsRelay(directory / "dns.sock", stub)
    relay.start()
    log.debug("DNS relay %s -> %s:53", relay.path, stub)
    return relay


def split_families(cidrs: Sequence[str]) -> tuple[list[str], list[str]]:
    v4_nets: list[ipaddress.IPv4Network] = []
    v6_nets: list[ipaddress.IPv6Network] = []
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.version == 4:
            v4_nets.append(net)
        else:
            v6_nets.append(net)

    def _collapsed_v4_text(nets: Sequence[ipaddress.IPv4Network]) -> list[str]:
        if not nets:
            return []
        collapsed = ipaddress.collapse_addresses(
            sorted(set(nets), key=lambda n: (int(n.network_address), n.prefixlen))
        )
        return [str(net) for net in collapsed]

    def _collapsed_v6_text(nets: Sequence[ipaddress.IPv6Network]) -> list[str]:
        if not nets:
            return []
        collapsed = ipaddress.collapse_addresses(
            sorted(set(nets), key=lambda n: (int(n.network_address), n.prefixlen))
        )
        return [str(net) for net in collapsed]

    return _collapsed_v4_text(v4_nets), _collapsed_v6_text(v6_nets)


def _deny_covers(deny: Sequence[str], addr: str) -> bool:
    """True when ``addr`` is already inside one of the deny CIDRs."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    for cidr in deny:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def build_nft_ruleset(
    net: NetworkConfig,
    *,
    extra_allow: Sequence[str] = (),
    dns_allow: Sequence[str] = (),
    dns_proxy: bool = False,
    port_gateway: str | None = None,
) -> str:
    """Build an nftables ruleset for the sandbox netns."""
    allow = list(dict.fromkeys([*extra_allow, *net.allow]))
    if dns_proxy:
        allow = list(dict.fromkeys([*allow, "127.0.0.1/32"]))
    deny = list(dict.fromkeys(net.deny))
    # The port gateway is how the sandbox reaches host listeners for published
    # container ports. Every other port on that address stays denied.
    if port_gateway and not _deny_covers(deny, port_gateway):
        deny.append(f"{port_gateway}/32")
    allow4, allow6 = split_families(allow)
    deny4, deny6 = split_families(deny)
    dns4, dns6 = split_families(dns_allow)

    # A base chain policy can only be accept or drop. Deny mode still rejects
    # with an explicit rule so guests fail fast; policy drop is the backstop.
    default_policy = "accept" if net.policy == "allow" else "drop"

    def set_elements(items: list[str]) -> str:
        return ", ".join(items)

    lines = [
        "flush ruleset",
        "table inet buddelkiste {",
        "  set allow4 {",
        "    type ipv4_addr",
        "    flags interval",
        *( [f"    elements = {{ {set_elements(allow4)} }}"] if allow4 else [] ),
        "  }",
        "  set allow6 {",
        "    type ipv6_addr",
        "    flags interval",
        *( [f"    elements = {{ {set_elements(allow6)} }}"] if allow6 else [] ),
        "  }",
        "  set dyn_allow4 {",
        "    type ipv4_addr",
        "    flags timeout",
        "  }",
        "  set dyn_allow6 {",
        "    type ipv6_addr",
        "    flags timeout",
        "  }",
        "  set dns4 {",
        "    type ipv4_addr",
        "    flags interval",
        *( [f"    elements = {{ {set_elements(dns4)} }}"] if dns4 else [] ),
        "  }",
        "  set dns6 {",
        "    type ipv6_addr",
        "    flags interval",
        *( [f"    elements = {{ {set_elements(dns6)} }}"] if dns6 else [] ),
        "  }",
        "  set deny4 {",
        "    type ipv4_addr",
        "    flags interval",
        *( [f"    elements = {{ {set_elements(deny4)} }}"] if deny4 else [] ),
        "  }",
        "  set deny6 {",
        "    type ipv6_addr",
        "    flags interval",
        *( [f"    elements = {{ {set_elements(deny6)} }}"] if deny6 else [] ),
        "  }",
        *(
            [
                "  set fwd_ports {",
                "    type inet_service",
                "  }",
            ]
            if port_gateway
            else []
        ),
        "  chain output {",
        f"    type filter hook output priority 0; policy {default_policy};",
        "    oifname \"lo\" accept",
        "    ct state established,related accept",
        # Nameserver and allow-host addresses are accepted before the private
        # deny presets. Otherwise split-DNS resolvers and allowed names that
        # live in RFC1918 are rejected even though policy allow would pass them.
        "    ip daddr @dns4 tcp dport 53 accept",
        "    ip daddr @dns4 udp dport 53 accept",
        "    ip6 daddr @dns6 tcp dport 53 accept",
        "    ip6 daddr @dns6 udp dport 53 accept",
        "    ip daddr @dyn_allow4 accept",
        "    ip6 daddr @dyn_allow6 accept",
        *(
            [f"    ip daddr {port_gateway} tcp dport @fwd_ports accept"]
            if port_gateway
            else []
        ),
        "    ip daddr @deny4 reject",
        "    ip6 daddr @deny6 reject",
        "    ip daddr @allow4 accept",
        "    ip6 daddr @allow6 accept",
        *(["    reject"] if net.policy == "deny" else []),
        "  }",
    ]
    if dns_proxy:
        lines += [
            "  chain dns_redirect {",
            "    type nat hook output priority -100; policy accept;",
            # UDP only: the proxy listens on UDP and forwards upstream over TCP
            # specifically so those fetches are not caught by this redirect.
            f"    meta l4proto udp udp dport 53 redirect to :{DNS_PROXY_PORT}",
            "  }",
        ]
    lines += [
        "}",
    ]
    return "\n".join(lines) + "\n"


# When set to pasta or slirp4netns, filter mode uses that backend.
NET_HELPER_ENV = "BUDDELKISTE_NET_HELPER"
_NET_HELPERS = ("pasta", "slirp4netns")


def find_net_helper() -> tuple[str, str]:
    """Return (kind, path) for pasta or slirp4netns.

    ``BUDDELKISTE_NET_HELPER`` picks one when both are installed. Unset, pasta
    wins and slirp4netns is the fallback.
    """
    forced = os.environ.get(NET_HELPER_ENV)
    if forced:
        if forced not in _NET_HELPERS:
            raise click.ClickException(
                f"{NET_HELPER_ENV} must be pasta or slirp4netns (got {forced!r})"
            )
        path = which(forced)
        if not path:
            raise click.ClickException(
                f"{NET_HELPER_ENV}={forced} but {forced} is not on PATH"
            )
        return forced, path
    pasta = which("pasta")
    if pasta:
        return "pasta", pasta
    slirp = which("slirp4netns")
    if slirp:
        return "slirp4netns", slirp
    raise click.ClickException(
        "network.mode=filter requires pasta (passt) or slirp4netns on PATH"
    )


def ensure_filter_tools() -> None:
    if not which("nft"):
        raise click.ClickException("network.mode=filter requires nft (nftables) on PATH")
    if not which("setpriv"):
        raise click.ClickException("network.mode=filter requires setpriv (util-linux) on PATH")
    find_net_helper()


def with_share_net(bwrap_args: list[str]) -> list[str]:
    """Insert --share-net after --unshare-all (or at front of options)."""
    args = list(bwrap_args)
    if "--share-net" in args:
        return args
    try:
        idx = args.index("--unshare-all")
        args.insert(idx + 1, "--share-net")
    except ValueError:
        args[1:1] = ["--share-net"]
    return args


def _replace_ro_bind_target(args: list[str], target: str, source: str) -> list[str]:
    """Replace first --ro-bind source for a given target; insert before ``--`` if missing."""
    out = list(args)
    i = 0
    while i + 2 < len(out):
        if out[i] == "--ro-bind" and out[i + 2] == target:
            out[i + 1] = source
            return out
        i += 1
    if "--" in out:
        idx = out.index("--")
        return [*out[:idx], "--ro-bind", source, target, *out[idx:]]
    return [*out, "--ro-bind", source, target]


def apply_nft_ruleset(ruleset: str) -> None:
    proc = subprocess.run(
        ["nft", "-f", "-"],
        input=ruleset,
        text=True,
        check=False,
        capture_output=True,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise click.ClickException(f"failed to install nftables rules: {detail}")


def _child_namespaces_ready(pid: int) -> bool:
    """True once ``pid`` is in a user and network namespace other than ours."""
    try:
        own_user = os.readlink("/proc/self/ns/user")
        own_net = os.readlink("/proc/self/ns/net")
        return (
            os.readlink(f"/proc/{pid}/ns/user") != own_user
            and os.readlink(f"/proc/{pid}/ns/net") != own_net
        )
    except OSError:
        return False


def _wait_for_tap(name: str = "tap0", timeout: float = 5) -> None:
    """Wait until slirp, running in the parent, has created ``name`` here."""
    deadline = time.monotonic() + timeout
    devs: list[str] = []
    while time.monotonic() < deadline:
        try:
            lines = Path("/proc/net/dev").read_text(encoding="utf-8").splitlines()
            devs = [line.split(":", 1)[0].strip() for line in lines[2:]]
        except OSError:
            devs = []
        if name in devs:
            return
        time.sleep(0.05)
    raise click.ClickException(f"timed out waiting for slirp4netns {name}")


def start_slirp4netns(
    slirp_bin: str,
    *,
    target_pid: int | None = None,
    userns_path: str | None = None,
    host_loopback: bool = False,
) -> subprocess.Popen:
    """Start slirp4netns and wait until it reports the tap is configured.

    ``/sys/class/net`` is the host sysfs mount, so ``tap0`` inside the new
    netns never shows up there. ``--ready-fd`` is slirp's own ready signal.
    The process must run in the host netns: its NAT sockets are how guest
    traffic leaves the machine. ``userns_path`` is required when the target
    pid is in a user namespace this process is not part of.
    """
    pid = os.getpid() if target_pid is None else target_pid
    read_fd, write_fd = os.pipe()
    os.set_inheritable(write_fd, True)
    argv = [
        slirp_bin,
        "--configure",
        "--mtu=65520",
    ]
    # Published container ports listen on the host. With this flag, slirp drops
    # every connection to that loopback, including the port relay. nft still
    # rejects every other port on 10.0.2.2.
    if not host_loopback:
        argv.append("--disable-host-loopback")
    if userns_path:
        argv.extend(["--userns-path", userns_path])
    argv.extend(["--ready-fd", str(write_fd), str(pid), "tap0"])
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            pass_fds=(write_fd,),
        )
    except Exception:
        os.close(write_fd)
        os.close(read_fd)
        raise
    os.close(write_fd)
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                err = (proc.stderr.read() if proc.stderr else b"").decode("utf-8", "replace")
                raise click.ClickException(f"slirp4netns exited during startup: {err.strip()}")
            remaining = max(0.0, deadline - time.monotonic())
            readable, _, _ = select.select([read_fd], [], [], min(0.05, remaining))
            if readable:
                os.read(read_fd, 16)
                return proc
        proc.terminate()
        try:
            proc.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate(timeout=1)
        raise click.ClickException("timed out waiting for slirp4netns tap0")
    finally:
        os.close(read_fd)


def spawn_bwrap_dropped(bwrap_args: list[str]) -> subprocess.Popen:
    """Start bwrap after dropping CAP_NET_ADMIN in the child only."""
    cmd = [
        "setpriv",
        "--bounding-set=-net_admin",
        "--inh-caps=-net_admin",
        "--ambient-caps=-net_admin",
        "--",
        *with_share_net(bwrap_args),
    ]
    log.debug("spawn: %s", " ".join(cmd))
    return subprocess.Popen(cmd)


def preseed_host_allows(hosts: Sequence[str]) -> None:
    """Resolve allowlisted hostnames once and seed dynamic nft sets."""
    for host in hosts:
        if host.startswith("*."):
            continue
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError as exc:
            log.debug("preseed resolve %s failed: %s", host, exc)
            continue
        seen: set[str] = set()
        for info in infos:
            ip = str(info[4][0])
            if ip in seen:
                continue
            seen.add(ip)
            nft_add_allow_ip(ip, 300)


def run_network_inner(net: NetworkConfig, bwrap_args: list[str], *, start_slirp: bool) -> int:
    """Apply filter rules in the current netns, run optional DNS proxy, spawn bwrap."""
    if not which("nft"):
        raise click.ClickException("network.mode=filter requires nft (nftables) on PATH")
    if not which("setpriv"):
        raise click.ClickException("network.mode=filter requires setpriv (util-linux) on PATH")

    slirp_proc = None
    proxy: DnsProxy | None = None
    nsswitch_override: Path | None = None
    resolv_override: Path | None = None
    if start_slirp:
        # The parent starts slirp4netns in the host netns and points it at
        # this process. Waiting here keeps nftables off the interface until
        # the tap exists.
        _wait_for_tap()

    try:
        extra_allow = resolv_conf_nameservers()
        upstreams = nameserver_ips()
        relay = os.environ.get(DNS_RELAY_ENV)
        if start_slirp and not relay:
            # slirp4netns built-in DNS, used only when the host has no stub relay.
            extra_allow.append("10.0.2.3/32")
            if "10.0.2.3" not in upstreams:
                upstreams.append("10.0.2.3")

        # Hostname rules need the proxy so answers can update nft. A resolv.conf
        # that is only the systemd stub cannot be dialed from this netns; the
        # parent relays that socket to 127.0.0.53 and systemd-resolved chooses
        # the uplinks.
        use_proxy = net.needs_dns_proxy or not sandbox_nameservers()
        if use_proxy:
            if relay:
                upstreams = [relay]
            else:
                for ip in upstreams:
                    cidr = f"{ip}/{32 if ':' not in ip else 128}"
                    if cidr not in extra_allow:
                        extra_allow.append(cidr)

            # Route sandbox hostname resolution into the DNS proxy reliably.
            nss_lines: list[str]
            try:
                nss_lines = Path("/etc/nsswitch.conf").read_text(encoding="utf-8").splitlines()
            except OSError:
                nss_lines = []
            hosts_rewritten = False
            rewritten: list[str] = []
            for raw in nss_lines:
                stripped = raw.lstrip()
                if stripped.startswith("hosts:"):
                    indent = raw[: len(raw) - len(stripped)]
                    rewritten.append(f"{indent}hosts: files dns")
                    hosts_rewritten = True
                else:
                    rewritten.append(raw)
            if not hosts_rewritten:
                rewritten.append("hosts: files dns")
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                prefix="bk-nsswitch-",
                delete=False,
            ) as fh:
                fh.write("\n".join(rewritten) + "\n")
                nsswitch_override = Path(fh.name)
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                prefix="bk-resolv-",
                delete=False,
            ) as fh:
                fh.write("nameserver 127.0.0.1\noptions attempts:1 timeout:4\n")
                resolv_override = Path(fh.name)
            bwrap_args = _replace_ro_bind_target(
                bwrap_args, "/etc/nsswitch.conf", str(nsswitch_override)
            )
            bwrap_args = _replace_ro_bind_target(
                bwrap_args, "/etc/resolv.conf", str(resolv_override)
            )

        listen_port = DNS_PROXY_PORT
        if use_proxy:
            # Prefer :53 in the isolated netns so glibc's nameserver 127.0.0.1
            # hits the proxy without nft NAT redirect (often unsupported here).
            if "127.0.0.1/32" not in extra_allow:
                extra_allow.append("127.0.0.1/32")
            try:
                proxy = DnsProxy(
                    upstreams=upstreams,
                    allow_hosts=net.allow_hosts,
                    deny_hosts=net.deny_hosts,
                    add_allow_ip=nft_add_allow_ip,
                    listen_host="127.0.0.1",
                    listen_port=53,
                )
                proxy.start()
                listen_port = 53
            except OSError:
                proxy = DnsProxy(
                    upstreams=upstreams,
                    allow_hosts=net.allow_hosts,
                    deny_hosts=net.deny_hosts,
                    add_allow_ip=nft_add_allow_ip,
                )
                proxy.start()
                listen_port = DNS_PROXY_PORT

        dns_ips = []
        for ip in upstreams:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            dns_ips.append(ip)
        dns_allow = [f"{ip}/{32 if ':' not in ip else 128}" for ip in dns_ips]
        port_gateway = os.environ.get(PORT_GATEWAY_ENV) or None
        ruleset = build_nft_ruleset(
            net,
            extra_allow=extra_allow,
            dns_allow=dns_allow,
            dns_proxy=use_proxy and listen_port != 53,
            port_gateway=port_gateway,
        )
        if not use_proxy:
            log.debug("DNS proxy disabled upstreams=%s", upstreams)
        log.debug("nft ruleset:\n%s", ruleset)
        apply_nft_ruleset(ruleset)
        if use_proxy:
            preseed_host_allows(net.allow_hosts)

        port_relay: PublishedPortRelay | None = None
        docker_host = os.environ.get(DOCKER_HOST_ENV, "")
        try:
            if port_gateway and docker_host.startswith("unix://"):
                port_relay = PublishedPortRelay(docker_host, port_gateway)
                port_relay.start()
            proc = spawn_bwrap_dropped(bwrap_args)
            return proc.wait()
        finally:
            if port_relay is not None:
                port_relay.stop()
    finally:
        if proxy is not None:
            proxy.stop()
        if slirp_proc is not None and slirp_proc.poll() is None:
            slirp_proc.terminate()
        if nsswitch_override is not None:
            try:
                nsswitch_override.unlink(missing_ok=True)
            except OSError:
                pass
        if resolv_override is not None:
            try:
                resolv_override.unlink(missing_ok=True)
            except OSError:
                pass


def run_bwrap(bwrap_args: list[str], net: NetworkConfig) -> int:
    """Run bwrap under the requested network mode."""
    if net.mode == "host":
        return subprocess.run(with_share_net(bwrap_args), check=False).returncode

    if net.mode == "none":
        return subprocess.run(bwrap_args, check=False).returncode

    # filter
    ensure_filter_tools()
    kind, helper = find_net_helper()

    with tempfile.TemporaryDirectory(prefix="buddelkiste-net-") as tmp:
        tmp_path = Path(tmp)
        net_file = tmp_path / "network.json"
        bwrap_file = tmp_path / "bwrap.json"
        net_file.write_text(
            json.dumps(
                {
                    "mode": net.mode,
                    "policy": net.policy,
                    "allow": net.allow,
                    "deny": net.deny,
                    "allow_hosts": net.allow_hosts,
                    "deny_hosts": net.deny_hosts,
                    "allow_presets": net.allow_presets,
                    "deny_presets": net.deny_presets,
                }
            ),
            encoding="utf-8",
        )
        bwrap_file.write_text(json.dumps(bwrap_args), encoding="utf-8")

        inner = [
            sys.executable,
            "-m",
            "buddelkiste.network_inner",
            str(net_file),
            str(bwrap_file),
        ]
        # which() finds nft under /usr/sbin. The pasta child execs "nft" by
        # name, so that directory has to be on its PATH. Arch already has it
        # via the /usr/bin merge.
        child_env = os.environ.copy()
        child_env["PATH"] = path_with_tools(
            ("nft", "setpriv", "ip"), child_env.get("PATH")
        )
        relay = start_host_dns_relay(tmp_path)
        if relay is not None:
            child_env[DNS_RELAY_ENV] = str(relay.path)
        docker_host = sandbox_docker_host(bwrap_args)
        port_gateway = ""
        if docker_host:
            port_gateway = PASTA_PORT_GATEWAY if kind == "pasta" else SLIRP_PORT_GATEWAY
            child_env[PORT_GATEWAY_ENV] = port_gateway
            child_env[DOCKER_HOST_ENV] = docker_host

        try:
            if kind == "pasta":
                # pasta's spawn execs the command from the new namespaces. Debian
                # pasta 20250503 returns EACCES for a binary under a 0700 home
                # (the venv interpreter). /bin/sh is executable by everyone and
                # then execs the real argv, which newer pasta can do directly too.
                cmd = [
                    helper,
                    "--config-net",
                    # Newer pasta replaced --disable-host-loopback with this.
                    "--map-host-loopback",
                    port_gateway or "none",
                    "--",
                    "/bin/sh",
                    "-c",
                    'exec "$@"',
                    "buddelkiste-pasta",
                    *inner,
                ]
                log.debug("launch pasta filter: %s", " ".join(cmd))
                return subprocess.run(cmd, check=False, env=child_env).returncode

            # slirp4netns must run in the host netns. Its NAT sockets are the
            # guest's path out; starting it inside the new netns blackholes them.
            # The child only waits for tap0, then installs nftables.
            if not which("unshare"):
                raise click.ClickException("network.mode=filter with slirp4netns requires unshare")
            cmd = [
                "unshare",
                "--user",
                "--map-root-user",
                "--net",
                "--",
                *inner,
                "--start-slirp",
            ]
            log.debug("launch slirp filter: %s", " ".join(cmd))
            child = subprocess.Popen(cmd, env=child_env)
            slirp_proc = None
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if child.poll() is not None:
                        return child.returncode
                    if _child_namespaces_ready(child.pid):
                        slirp_proc = start_slirp4netns(
                            helper,
                            target_pid=child.pid,
                            userns_path=f"/proc/{child.pid}/ns/user",
                            host_loopback=bool(port_gateway),
                        )
                        break
                    time.sleep(0.02)
                else:
                    raise click.ClickException(
                        "timed out waiting for the filter network namespace"
                    )
                return child.wait()
            finally:
                if slirp_proc is not None and slirp_proc.poll() is None:
                    slirp_proc.terminate()
                    try:
                        slirp_proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        slirp_proc.kill()
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        child.kill()
        finally:
            if relay is not None:
                relay.stop()
