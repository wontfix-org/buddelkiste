"""Selective network isolation for the sandbox.

Modes:
  host   — share the host network (default; current behavior)
  none   — private empty netns (no connectivity)
  filter — private netns via pasta with in-namespace nftables.
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
import re
import socket
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from io import BufferedIOBase
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
    PublishedPortRelay,
    sandbox_docker_host,
)
from buddelkiste.which import log_cmdline, path_with_tools, which

log = logging.getLogger(__name__)


def relay_debug_stream(stream: BufferedIOBase, label: str) -> threading.Thread:
    """Log each line from ``stream`` as ``label: line`` until EOF."""
    logger = logging.getLogger("buddelkiste")

    def _read() -> None:
        try:
            for raw in iter(stream.readline, b""):
                if not isinstance(raw, bytes):
                    break
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line:
                    logger.debug("%s: %s", label, line)
        except Exception:
            logger.debug("%s: log relay stopped", label, exc_info=True)

    thread = threading.Thread(target=_read, name=f"bk-{label}-log", daemon=True)
    thread.start()
    return thread


def relay_debug_file(path: Path, label: str, stop: threading.Event) -> threading.Thread:
    """Tail ``path`` and log each line as ``label: line`` until ``stop`` is set."""
    logger = logging.getLogger("buddelkiste")

    def _emit(raw: bytes) -> None:
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if line:
            logger.debug("%s: %s", label, line)

    def _read() -> None:
        while not path.exists():
            if stop.wait(0.02):
                return
        try:
            with path.open("rb") as handle:
                while True:
                    raw = handle.readline()
                    if raw:
                        _emit(raw)
                        continue
                    if stop.is_set():
                        rest = handle.read()
                        if rest:
                            for part in rest.splitlines():
                                _emit(part)
                        return
                    stop.wait(0.02)
        except OSError as exc:
            logger.debug("%s: log relay stopped: %s", label, exc)

    thread = threading.Thread(target=_read, name=f"bk-{label}-log", daemon=True)
    thread.start()
    return thread


def _pasta_debug_launch(tmp_path: Path) -> tuple[list[str], str, bool]:
    """Return extra pasta args, the shell snippet, and whether stderr is piped.

    Piping is only safe when stderr is a tty. The spawned command restores
    ``/dev/tty``, so pasta's messages stay off the sandbox command's stderr.
    Otherwise pasta writes a log file the parent tails.
    """
    if not os.environ.get("BUDDELKISTE_DEBUG"):
        return [], 'exec "$@"', False
    if sys.stderr.isatty():
        return ["--debug"], 'exec 2>/dev/tty; exec "$@"', True
    return ["--debug", "--log-file", str(tmp_path / "pasta.log")], 'exec "$@"', False

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

    if "backend" in data:
        raise click.ClickException(
            f"network.backend {where} is no longer supported; filter mode uses "
            "pasta only, so remove the key"
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
    override mode and policy when given.

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


# systemd-resolved still serves this stub when NetworkManager leaves
# /etc/resolv.conf without nameserver lines and nsswitch uses ``resolve``.
RESOLVED_STUB_RESOLV = Path("/run/systemd/resolve/stub-resolv.conf")


def relay_stub_address(
    resolv: Path | None = None,
    *,
    resolved_stub: Path | None = None,
) -> str | None:
    """Loopback resolver the host netns should relay sandbox DNS to.

    ``/etc/resolv.conf`` wins when it lists only a loopback stub. A file with
    no nameserver lines is the NetworkManager + nss-resolve layout: glibc
    never dials that file, and systemd-resolved's stub
    (``/run/systemd/resolve/stub-resolv.conf``) is the resolver that holds
    the uplink list. A resolv.conf that already names a non-loopback server
    is left alone.
    """
    resolv_path = resolv or Path("/etc/resolv.conf")
    stub = stub_nameserver(resolv_path)
    if stub is not None:
        return stub
    if resolv_conf_nameservers(resolv_path):
        return None
    stub_path = resolved_stub if resolved_stub is not None else RESOLVED_STUB_RESOLV
    if not stub_path.is_file():
        return None
    return stub_nameserver(stub_path)


# systemd-resolved's DNS stub. The resolve NSS module is usable for the proxy
# only when this address accepts TCP/53 in the host netns.
RESOLVED_STUB_HOST = "127.0.0.53"

_NSS_STATUSES = ("success", "notfound", "unavail", "tryagain")
_LOCAL_HOSTS_MODULES = frozenset({"files", "myhostname", "mymachines"})
_MDNS_MINIMAL_MODULES = frozenset({"mdns4_minimal", "mdns_minimal"})
_HOSTS_TOKEN_RE = re.compile(r"\[[^\]]*\]|\S+")


@dataclass(frozen=True)
class DnsUpstream:
    """Where sandbox DNS queries go after the in-netns proxy.

    ``relay`` is a loopback resolver dialed from the host netns. ``forward``
    is the routable list dialed from the sandbox. Exactly one is set.
    """

    relay: str | None = None
    forward: tuple[str, ...] = ()


def _nss_default_actions() -> dict[str, str]:
    return {
        "success": "return",
        "notfound": "continue",
        "unavail": "continue",
        "tryagain": "continue",
    }


def _apply_nss_action(actions: dict[str, str], spec: str) -> None:
    text = spec.strip()
    if "=" not in text:
        return
    negate = text.startswith("!")
    body = text[1:] if negate else text
    status, action = body.split("=", 1)
    status = status.strip().lower()
    action = action.strip().lower()
    if negate:
        for name in _NSS_STATUSES:
            if name != status:
                actions[name] = action
        return
    actions[status] = action


def _parse_nss_actions(bracket: str) -> dict[str, str]:
    actions = _nss_default_actions()
    inner = bracket[1:-1] if bracket.startswith("[") and bracket.endswith("]") else bracket
    for spec in inner.split():
        _apply_nss_action(actions, spec)
    return actions


def hosts_nss_modules(text: str) -> tuple[str, list[tuple[str, dict[str, str]]]] | None:
    """Return the first ``hosts:`` line and its modules.

    ``None`` when the file has no hosts line. A ``[STATUS=ACTION]`` group
    belongs to the module before it. Actions left unspecified keep glibc's
    defaults (``success`` returns, every other status continues).
    """
    logical = ""
    continued = False
    found = False
    for raw in text.splitlines():
        if continued:
            logical = f"{logical} {raw.strip()}"
        else:
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not stripped.startswith("hosts:"):
                continue
            logical = stripped
            found = True
        continued = logical.endswith("\\")
        if continued:
            logical = logical[:-1].rstrip()
            continue
        break
    if not found or continued:
        return None
    rest = logical.split(":", 1)[1]
    modules: list[tuple[str, dict[str, str]]] = []
    for token in _HOSTS_TOKEN_RE.findall(rest):
        if token.startswith("#"):
            break
        if token.startswith("["):
            if not modules:
                raise click.ClickException(f"nsswitch hosts action before a module: {logical}")
            name, _previous = modules[-1]
            modules[-1] = (name, _parse_nss_actions(token))
            continue
        modules.append((token, _nss_default_actions()))
    return logical, modules


def _dns_port_open(host: str) -> bool:
    try:
        with socket.create_connection((host, 53), timeout=0.3):
            return True
    except OSError:
        return False


def _resolv_host_addresses(path: Path) -> list[str]:
    ips: list[str] = []
    for cidr in resolv_conf_nameservers(path):
        net = ipaddress.ip_network(cidr, strict=False)
        host_route = (net.version == 4 and net.prefixlen == 32) or (
            net.version == 6 and net.prefixlen == 128
        )
        if host_route:
            ips.append(str(net.network_address))
    return ips


def resolv_conf_search_lines(path: Path | None = None) -> list[str]:
    """``search`` and ``domain`` lines from resolv.conf, in file order."""
    resolv = path or Path("/etc/resolv.conf")
    try:
        lines = resolv.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    found: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        kind = stripped.split(maxsplit=1)[0]
        if kind in {"search", "domain"}:
            found.append(stripped)
    return found


def proxy_resolv_text(*, include_search: bool, resolv: Path | None = None) -> str:
    """resolv.conf for the sandbox DNS proxy listener on 127.0.0.1.

    Search domains are copied only when the proxy dials public upstreams.
    A host stub or dnsmasq applies its own search list to the relayed query.
    """
    lines = ["nameserver 127.0.0.1"]
    if include_search:
        lines.extend(resolv_conf_search_lines(resolv))
    lines.append("options attempts:1 timeout:4")
    return "\n".join(lines) + "\n"


def _abort_hosts(line: str, module: str) -> None:
    raise click.ClickException(
        f"unsupported hosts module {module!r} in {line!r}. Filter mode can relay "
        "a live systemd-resolved stub (127.0.0.53) or follow the glibc dns module "
        "via /etc/resolv.conf."
    )


def _upstream_from_resolv(path: Path, probe: Callable[[str], bool]) -> DnsUpstream:
    addrs = _resolv_host_addresses(path)
    if not addrs:
        raise click.ClickException(f"glibc dns has no usable nameserver in {path}")
    if ipaddress.ip_address(addrs[0]).is_loopback:
        if not probe(addrs[0]):
            raise click.ClickException(
                f"loopback nameserver {addrs[0]} in {path} is not accepting DNS"
            )
        return DnsUpstream(relay=addrs[0])
    forward = tuple(addr for addr in addrs if not ipaddress.ip_address(addr).is_loopback)
    if not forward:
        raise click.ClickException(f"glibc dns has no routable nameserver in {path}")
    return DnsUpstream(forward=forward)


def plan_dns_upstream(
    nsswitch: Path | None = None,
    resolv: Path | None = None,
    *,
    stub_open: Callable[[str], bool] | None = None,
) -> DnsUpstream:
    """Choose the sandbox DNS upstream from the host ``hosts:`` line.

    Walk modules in order. ``files``, ``myhostname``, and ``mymachines`` are
    local and skipped. ``resolve`` relays to ``127.0.0.53`` when that stub
    accepts a connection; ``[!UNAVAIL=return]`` continues when it does not.
    ``dns`` uses ``/etc/resolv.conf`` (a leading loopback address is a relay,
    otherwise the routable addresses). ``mdns4_minimal`` and ``mdns_minimal``
    warn and continue. Any other module aborts filter mode.

    A missing nsswitch file or a file with no ``hosts:`` line is glibc's
    built-in ``dns`` path.
    """
    nss_path = nsswitch or Path("/etc/nsswitch.conf")
    resolv_path = resolv or Path("/etc/resolv.conf")
    probe = stub_open if stub_open is not None else _dns_port_open
    try:
        text = nss_path.read_text(encoding="utf-8")
    except OSError:
        parsed = None
    else:
        parsed = hosts_nss_modules(text)
    if parsed is None:
        modules_line = "hosts: dns"
        modules: list[tuple[str, dict[str, str]]] = [("dns", _nss_default_actions())]
    else:
        modules_line, modules = parsed

    warned_mdns = False
    for name, actions in modules:
        if name in _LOCAL_HOSTS_MODULES:
            continue
        if name in _MDNS_MINIMAL_MODULES:
            if actions.get("unavail") != "continue":
                _abort_hosts(modules_line, name)
            if not warned_mdns:
                log.warning(
                    "nsswitch module %s is not proxied; .local names will not "
                    "resolve in the sandbox",
                    name,
                )
                warned_mdns = True
            continue
        if name == "resolve":
            if probe(RESOLVED_STUB_HOST):
                return DnsUpstream(relay=RESOLVED_STUB_HOST)
            if actions.get("unavail") == "continue":
                continue
            raise click.ClickException(
                "systemd-resolved stub 127.0.0.53:53 is not accepting connections, "
                f"and {modules_line!r} does not fall through on unavail"
            )
        if name == "dns":
            return _upstream_from_resolv(resolv_path, probe)
        _abort_hosts(modules_line, name)
    raise click.ClickException(
        f"no supported DNS module in {modules_line!r}. Filter mode relays "
        "systemd-resolved's stub or follows the glibc dns module."
    )


# Passed to the filter child: Unix socket of a relay running in the host netns.
DNS_RELAY_ENV = "BUDDELKISTE_DNS_RELAY"


def start_host_dns_relay(directory: Path) -> HostDnsRelay | None:
    """Relay sandbox DNS to a host loopback resolver, when ``hosts:`` asks for one.

    The listener stays in this process, which is still in the host netns, so
    it can dial ``127.0.0.53`` or another loopback nameserver. The guest only
    sees the socket path. Raises ``click.ClickException`` when the hosts line
    is not a live resolved stub or the glibc ``dns`` module.
    """
    upstream = plan_dns_upstream()
    if upstream.relay is None:
        return None
    relay = HostDnsRelay(directory / "dns.sock", upstream.relay)
    relay.start()
    log.debug("DNS relay %s -> %s:53", relay.path, upstream.relay)
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


def find_net_helper() -> str:
    """Return the path to pasta, the only filter-mode userspace helper."""
    path = which("pasta")
    if not path:
        raise click.ClickException("network.mode=filter requires pasta (passt) on PATH")
    return path


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
    """Point ``target`` at ``source`` with ``--ro-bind``.

    Replaces an existing ``--ro-bind`` of ``target``. A ``--symlink`` whose
    destination is ``target`` is replaced too: bwrap refuses to mount onto a
    symlink it already created (host ``/etc/resolv.conf`` followed to the
    systemd stub). Otherwise the bind is inserted before ``--``.
    """
    out = list(args)
    i = 0
    symlink_at: int | None = None
    while i + 2 < len(out):
        if out[i] == "--symlink" and out[i + 2] == target and symlink_at is None:
            symlink_at = i
        if out[i] == "--ro-bind" and out[i + 2] == target:
            out[i + 1] = source
            return out
        i += 1
    if symlink_at is not None:
        out[symlink_at : symlink_at + 3] = ["--ro-bind", source, target]
        return out
    if "--" in out:
        idx = out.index("--")
        return [*out[:idx], "--ro-bind", source, target, *out[idx:]]
    return [*out, "--ro-bind", source, target]


def apply_nft_ruleset(ruleset: str) -> None:
    cmd = ["nft", "-f", "-"]
    log_cmdline(cmd, label="nft")
    proc = subprocess.run(
        cmd,
        input=ruleset,
        text=True,
        check=False,
        capture_output=True,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise click.ClickException(f"failed to install nftables rules: {detail}")


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
    log_cmdline(cmd, label="setpriv")
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


def run_network_inner(net: NetworkConfig, bwrap_args: list[str]) -> int:
    """Apply filter rules in the current netns, run optional DNS proxy, spawn bwrap."""
    if not which("nft"):
        raise click.ClickException("network.mode=filter requires nft (nftables) on PATH")
    if not which("setpriv"):
        raise click.ClickException("network.mode=filter requires setpriv (util-linux) on PATH")

    proxy: DnsProxy | None = None
    nsswitch_override: Path | None = None
    resolv_override: Path | None = None

    try:
        extra_allow = resolv_conf_nameservers()
        upstreams = nameserver_ips()
        relay = os.environ.get(DNS_RELAY_ENV)

        # Hostname rules need the proxy so answers can update nft. A resolv.conf
        # that is only the systemd stub cannot be dialed from this netns; the
        # parent relays that socket to 127.0.0.53 and systemd-resolved chooses
        # the uplinks. The relay is also set when hosts: uses resolve even if
        # resolv.conf lists public addresses those lookups never dial.
        use_proxy = bool(relay) or net.needs_dns_proxy or not sandbox_nameservers()
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
                fh.write(proxy_resolv_text(include_search=not relay))
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
        cmd = with_share_net(bwrap_args)
        log_cmdline(cmd, label="bwrap")
        return subprocess.run(cmd, check=False).returncode

    if net.mode == "none":
        log_cmdline(bwrap_args, label="bwrap")
        return subprocess.run(bwrap_args, check=False).returncode

    # filter
    ensure_filter_tools()
    helper = find_net_helper()

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
            port_gateway = PASTA_PORT_GATEWAY
            child_env[PORT_GATEWAY_ENV] = port_gateway
            child_env[DOCKER_HOST_ENV] = docker_host

        try:
            # pasta's spawn execs the command from the new namespaces. Debian
            # pasta 20250503 returns EACCES for a binary under a 0700 home
            # (the venv interpreter). /bin/sh is executable by everyone and
            # then execs the real argv, which newer pasta can do directly too.
            extra, shell, pipe_stderr = _pasta_debug_launch(tmp_path)
            cmd = [
                helper,
                *extra,
                # Skip the host IPv6 route scan and resolv.conf read. Without
                # these, pasta warns "No interfaces with usable IPv6 routes"
                # and "Couldn't get any nameserver address" and still
                # continues. The sandbox uses the DNS proxy, not pasta's
                # advertised resolvers.
                "--ipv4-only",
                "--dns",
                "none",
                "--search",
                "none",
                "--config-net",
                # Newer pasta replaced --disable-host-loopback with this.
                "--map-host-loopback",
                port_gateway or "none",
                "--",
                "/bin/sh",
                "-c",
                shell,
                "buddelkiste-pasta",
                *inner,
            ]
            log_cmdline(cmd, label="pasta")
            if pipe_stderr:
                proc = subprocess.Popen(cmd, env=child_env, stderr=subprocess.PIPE)
                follower = None
                if isinstance(proc.stderr, BufferedIOBase):
                    follower = relay_debug_stream(proc.stderr, "pasta")
                try:
                    return proc.wait()
                finally:
                    if follower is not None:
                        follower.join(timeout=2)
            if "--log-file" in extra:
                stop = threading.Event()
                follower = relay_debug_file(tmp_path / "pasta.log", "pasta", stop)
                try:
                    return subprocess.run(cmd, check=False, env=child_env).returncode
                finally:
                    stop.set()
                    follower.join(timeout=2)
            return subprocess.run(cmd, check=False, env=child_env).returncode
        finally:
            if relay is not None:
                relay.stop()
