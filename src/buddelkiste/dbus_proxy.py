"""Filter policy for the ``dbus-proxy`` feature (xdg-dbus-proxy).

With no rules the proxy is unfiltered (full session bus). xdg-dbus-proxy rejects
a bare ``*`` name, so the old ``--see=*`` / ``--talk=*`` / ``--own=*`` flags are
not used. Any ``see`` / ``talk`` / ``own`` / ``call`` / ``broadcast`` entry from
config or the CLI passes ``--filter`` and only those rules.

Names are well-known bus names. A ``.*`` suffix matches that name and its
children (``org.foo.*`` matches ``org.foo`` and ``org.foo.bar``, not
``org.foobar``). ``talk`` implies see for that name; ``own`` implies talk and
see. ``call`` and ``broadcast`` values are ``NAME=RULE``, where RULE is
``[METHOD][@PATH]``.
"""

from __future__ import annotations

import re
from collections.abc import Generator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

import click

POLICY_KEYS = ("see", "talk", "own", "call", "broadcast")

_BUS_ELEMENT = r"[A-Za-z_][A-Za-z0-9_-]*"
_BUS_NAME_RE = re.compile(rf"{_BUS_ELEMENT}(?:\.{_BUS_ELEMENT})+")
_BUS_NAME_RULE_RE = re.compile(rf"{_BUS_ELEMENT}(?:\.{_BUS_ELEMENT})+(?:\.\*)?")
_MEMBER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_PATH_ELEMENT_RE = re.compile(r"[A-Za-z0-9_]+")


@dataclass(frozen=True)
class DBusProxyPolicy:
    """Rules passed to xdg-dbus-proxy.

    ``filtered`` is true when config or the CLI supplied any policy key, including
    an explicit empty list. Unfiltered means the proxy is started without
    ``--filter``.
    """

    filtered: bool = False
    see: tuple[str, ...] = ()
    talk: tuple[str, ...] = ()
    own: tuple[str, ...] = ()
    call: tuple[str, ...] = ()
    broadcast: tuple[str, ...] = ()


@dataclass(frozen=True)
class _CliOverrides:
    executable: str | None = None
    see: tuple[str, ...] = ()
    talk: tuple[str, ...] = ()
    own: tuple[str, ...] = ()
    call: tuple[str, ...] = ()
    broadcast: tuple[str, ...] = ()


_cli_overrides: ContextVar[_CliOverrides | None] = ContextVar(
    "bk_dbus_proxy_cli", default=None
)


@contextmanager
def dbus_proxy_cli_context(
    *,
    executable: str | None = None,
    see: Sequence[str] = (),
    talk: Sequence[str] = (),
    own: Sequence[str] = (),
    call: Sequence[str] = (),
    broadcast: Sequence[str] = (),
) -> Generator[None, None, None]:
    """Apply ``bk run`` dbus-proxy flags for this process."""
    token = _cli_overrides.set(
        _CliOverrides(
            executable=executable,
            see=tuple(see),
            talk=tuple(talk),
            own=tuple(own),
            call=tuple(call),
            broadcast=tuple(broadcast),
        )
    )
    try:
        yield
    finally:
        _cli_overrides.reset(token)


def dbus_proxy_command_args(policy: DBusProxyPolicy) -> list[str]:
    """xdg-dbus-proxy filter arguments for ``policy``."""
    if not policy.filtered:
        return []
    args = ["--filter"]
    for flag, values in (
        ("see", policy.see),
        ("talk", policy.talk),
        ("own", policy.own),
        ("call", policy.call),
        ("broadcast", policy.broadcast),
    ):
        args.extend(f"--{flag}={value}" for value in values)
    return args


def resolve_dbus_proxy(
    config: Mapping[str, object] | None = None,
    *,
    executable: str | None = None,
    see: Sequence[str] = (),
    talk: Sequence[str] = (),
    own: Sequence[str] = (),
    call: Sequence[str] = (),
    broadcast: Sequence[str] = (),
) -> DBusProxyPolicy:
    """Resolve dbus-proxy filter rules.

    Precedence for each key: omitted means unset. Global ``[dbus_proxy]`` sets
    the list; ``executables.<name>.dbus_proxy`` replaces that same key;
    CLI flags append. Filtering turns on when any key is set. Duplicate rules
    are dropped, first occurrence wins.
    """
    overrides = _cli_overrides.get()
    if overrides is not None:
        if executable is None:
            executable = overrides.executable
        see = (*overrides.see, *see)
        talk = (*overrides.talk, *talk)
        own = (*overrides.own, *own)
        call = (*overrides.call, *call)
        broadcast = (*overrides.broadcast, *broadcast)

    chosen: dict[str, list[str]] = {}
    data = dict(config or {})
    if "dbus_proxy" in data:
        chosen.update(_parse_table(data["dbus_proxy"], where="dbus_proxy"))

    exec_table = _executable_dbus_proxy(data, executable)
    if exec_table is not None:
        chosen.update(exec_table)

    cli_values = {
        "see": see,
        "talk": talk,
        "own": own,
        "call": call,
        "broadcast": broadcast,
    }
    for key, values in cli_values.items():
        if not values:
            continue
        bucket = chosen.setdefault(key, [])
        where = f"--dbus-{key}"
        for item in values:
            bucket.append(_validate_entry(key, item, where=where))

    if not chosen:
        return DBusProxyPolicy()

    return DBusProxyPolicy(
        filtered=True,
        see=_dedupe(chosen.get("see", ())),
        talk=_dedupe(chosen.get("talk", ())),
        own=_dedupe(chosen.get("own", ())),
        call=_dedupe(chosen.get("call", ())),
        broadcast=_dedupe(chosen.get("broadcast", ())),
    )


def _executable_dbus_proxy(
    config: Mapping[str, object],
    executable: str | None,
) -> dict[str, list[str]] | None:
    if not executable:
        return None
    from buddelkiste.features import lookup_executable_config

    exec_cfg = lookup_executable_config(dict(config), executable)
    if exec_cfg is None or "dbus_proxy" not in exec_cfg:
        return None
    where = f"executables.{executable}.dbus_proxy"
    return _parse_table(exec_cfg["dbus_proxy"], where=where)


def _parse_table(raw: object, *, where: str) -> dict[str, list[str]]:
    if not isinstance(raw, Mapping):
        raise click.ClickException(f"{where} must be a table")
    unknown = [str(key) for key in raw if str(key) not in POLICY_KEYS]
    if unknown:
        allowed = ", ".join(POLICY_KEYS)
        names = ", ".join(unknown)
        raise click.ClickException(f"{where}: unknown key {names} (expected {allowed})")

    parsed: dict[str, list[str]] = {}
    for key in POLICY_KEYS:
        if key not in raw:
            continue
        parsed[key] = _parse_list(raw[key], key=key, where=f"{where}.{key}")
    return parsed


def _parse_list(raw: object, *, key: str, where: str) -> list[str]:
    if not isinstance(raw, list):
        raise click.ClickException(f"{where} must be a list of strings")
    values: list[str] = []
    for index, item in enumerate(raw):
        if not isinstance(item, str):
            raise click.ClickException(f"{where}[{index}] must be a string")
        values.append(_validate_entry(key, item, where=f"{where}[{index}]"))
    return values


def _validate_entry(key: str, value: str, *, where: str) -> str:
    if key in {"see", "talk", "own"}:
        _validate_bus_name(value, where=where)
        return value
    _validate_name_rule(value, where=where)
    return value


def _validate_bus_name(name: str, *, where: str) -> None:
    if len(name) > 255 or _BUS_NAME_RULE_RE.fullmatch(name) is None:
        raise click.ClickException(
            f"{where}: {name!r} is not a valid D-Bus well-known name "
            "(optional .* suffix matches that name and its children)"
        )


def _validate_name_rule(value: str, *, where: str) -> None:
    name, sep, rule = value.partition("=")
    if not sep:
        raise click.ClickException(f"{where}: expected NAME=RULE, got {value!r}")
    _validate_bus_name(name, where=where)
    if _valid_rule(rule):
        return
    raise click.ClickException(
        f"{where}: invalid rule {rule!r} "
        "(expected [METHOD][@PATH]; METHOD is *, an interface, interface.*, "
        "or interface.member; PATH is an object path with an optional /* suffix)"
    )


def _valid_rule(rule: str) -> bool:
    if any(char.isspace() or char == "=" for char in rule):
        return False
    method, sep, path = rule.partition("@")
    if sep and not _valid_object_path(path):
        return False
    return not method or _valid_method(method)


def _valid_method(method: str) -> bool:
    if method == "*":
        return True
    if method.endswith(".*"):
        return _BUS_NAME_RE.fullmatch(method[:-2]) is not None
    if "." not in method:
        return False
    interface, member = method.rsplit(".", 1)
    return (
        _BUS_NAME_RE.fullmatch(interface) is not None
        and _MEMBER_RE.fullmatch(member) is not None
    )


def _valid_object_path(path: str) -> bool:
    body = path.removesuffix("/*")
    if not body.startswith("/") or not body or len(path) > 255:
        return False
    if body == "/":
        return not path.endswith("/*")
    if body.endswith("/") or "//" in body:
        return False
    return all(_PATH_ELEMENT_RE.fullmatch(element) for element in body[1:].split("/"))


def _dedupe(values: Sequence[str]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for value in values:
        seen.setdefault(value, None)
    return tuple(seen)
