"""Detect conflicting sandbox mounts and environment assignments before launch."""

from __future__ import annotations

import os
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import click

from buddelkiste.binds import (
    DEFAULT_BIND_SYMLINKS,
    BasicBindConfig,
    OverlayBindConfig,
    SymlinkConfig,
    Tmpfs,
    TmpOverlayBindConfig,
    apply_one_bind_symlink,
    normalize_bind_symlinks,
)
from buddelkiste.features import (
    BASE_ENV_VARS,
    binds_from_spec,
    enabled_feature_names,
    load_feature_registry,
)


@dataclass(frozen=True)
class MountClaim:
    """A filesystem mount that will appear at ``target`` inside the sandbox."""

    target: str
    kind: str
    source: str | None
    origin: str

    @property
    def identity(self) -> tuple[str, str | None]:
        return (self.kind, self.source)

    def describe(self) -> str:
        if self.source is None:
            return f"{self.kind} ({self.origin})"
        if self.source == self.target:
            return f"{self.kind} {self.source} ({self.origin})"
        return f"{self.kind} {self.source} -> {self.target} ({self.origin})"


@dataclass(frozen=True)
class EnvClaim:
    """An environment variable that will be set inside the sandbox."""

    name: str
    value: str
    origin: str

    def describe(self) -> str:
        return f"{self.name}={self.value!r} ({self.origin})"


_BIND_FLAG_KIND = {
    "--ro-bind": "ro-bind",
    "--bind": "bind",
    "--dev-bind": "dev-bind",
    "--ro-bind-try": "ro-bind-try",
    "--bind-try": "bind-try",
    "--dev-bind-try": "dev-bind-try",
}

# Read-only is weaker; read-write is stronger. Overlay / tmpfs / dev-bind are
# not ranked and cannot be resolved by bind_conflicts.
_RO_KINDS = frozenset({"ro-bind", "ro-bind-try"})
_RW_KINDS = frozenset({"bind", "bind-try"})
BIND_CONFLICT_POLICIES = ("error", "stronger", "weaker")
DEFAULT_BIND_CONFLICTS = "error"


def normalize_bind_conflicts(raw: object, *, where: str = "bind_conflicts") -> str:
    """Return ``error``, ``stronger``, or ``weaker``."""
    if not isinstance(raw, str):
        allowed = ", ".join(repr(item) for item in BIND_CONFLICT_POLICIES)
        raise click.ClickException(f"{where} must be {allowed} (got {raw!r})")
    value = raw.strip().lower()
    if value not in BIND_CONFLICT_POLICIES:
        allowed = ", ".join(repr(item) for item in BIND_CONFLICT_POLICIES)
        raise click.ClickException(f"{where} must be {allowed} (got {raw!r})")
    return value


def bind_conflict_policy(config: Mapping | None = None) -> str:
    """Return the global ``bind_conflicts`` policy (default ``error``)."""
    if not config or "bind_conflicts" not in config:
        return DEFAULT_BIND_CONFLICTS
    return normalize_bind_conflicts(config["bind_conflicts"])


def bind_symlink_policy(config: Mapping | None = None) -> str:
    """Return the global ``bind_symlinks`` policy (default ``follow``)."""
    if not config or "bind_symlinks" not in config:
        return DEFAULT_BIND_SYMLINKS
    try:
        return normalize_bind_symlinks(config["bind_symlinks"])
    except (TypeError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc


def _bind_mode_rank(kind: str) -> int | None:
    if kind in _RO_KINDS:
        return 0
    if kind in _RW_KINDS:
        return 1
    return None


def _norm_source(source: str | None) -> str | None:
    if source is None:
        return None
    return _norm_target(source)


def _resolvable_ro_rw_conflict(claims: Sequence[MountClaim]) -> bool:
    """True when claims differ only by ro vs rw for one source and target."""
    ranks = {_bind_mode_rank(claim.kind) for claim in claims}
    if ranks != {0, 1}:
        return False
    sources = {_norm_source(claim.source) for claim in claims}
    return len(sources) == 1


def _winning_mode_rank(claims: Sequence[MountClaim], policy: str) -> int:
    ranks = [
        rank
        for claim in claims
        if (rank := _bind_mode_rank(claim.kind)) is not None
    ]
    return max(ranks) if policy == "stronger" else min(ranks)


def resolve_bind_conflicts(binds: Sequence[object], policy: str) -> list:
    """Drop the losing ro/rw bind when ``policy`` is ``stronger`` or ``weaker``.

    ``error`` leaves the list unchanged so launch-time conflict detection can
    report both sides. Other mismatches (different sources, overlay, tmpfs)
    are not collapsed.
    """
    policy = normalize_bind_conflicts(policy)
    if policy == "error":
        return list(binds)

    entries: list[tuple[object, list[MountClaim]]] = []
    by_target: dict[str, list[int]] = defaultdict(list)
    for bind in binds:
        claims = claims_from_bind(bind, "bind")
        index = len(entries)
        entries.append((bind, claims))
        seen_targets: set[str] = set()
        for claim in claims:
            if claim.target in seen_targets:
                continue
            seen_targets.add(claim.target)
            by_target[claim.target].append(index)

    drop: set[int] = set()
    for target, indexes in by_target.items():
        group = [
            claim
            for index in indexes
            for claim in entries[index][1]
            if claim.target == target
        ]
        if not _resolvable_ro_rw_conflict(group):
            continue
        win = _winning_mode_rank(group, policy)
        for index in indexes:
            for claim in entries[index][1]:
                if claim.target != target:
                    continue
                rank = _bind_mode_rank(claim.kind)
                if rank is not None and rank != win:
                    drop.add(index)
                    break

    return [bind for index, (bind, _claims) in enumerate(entries) if index not in drop]


def _norm_target(path: Path | str) -> str:
    return os.path.normpath(os.fspath(path))


def _kind_for_bind(bind: BasicBindConfig) -> str:
    if isinstance(bind, TmpOverlayBindConfig):
        return "tmp-overlay"
    if isinstance(bind, OverlayBindConfig):
        return "overlay"
    flag = bind.flag or ""
    return _BIND_FLAG_KIND.get(flag, flag.lstrip("-") or "bind")


def _source_for_bind(bind: BasicBindConfig) -> str:
    if isinstance(bind, OverlayBindConfig):
        return f"{os.fspath(bind.source)} (upper={os.fspath(bind.upper)})"
    return os.fspath(bind.source)


def claims_from_bind(bind: object, origin: str) -> list[MountClaim]:
    """Return mount claims emitted by a bind object (if it will be applied)."""
    from buddelkiste.binds import RWBindConfig

    if isinstance(bind, SymlinkConfig):
        return [
            MountClaim(
                target=_norm_target(bind.target),
                kind="symlink",
                source=os.fspath(bind.source),
                origin=origin,
            )
        ]

    if isinstance(bind, Tmpfs):
        return [
            MountClaim(
                target=_norm_target(bind.target),
                kind="tmpfs",
                source=None,
                origin=origin,
            )
        ]

    if isinstance(bind, BasicBindConfig):
        source = Path(os.fspath(bind.source))
        # Match bind ``__iter__``: missing sources are skipped. RW / overlay
        # binds create paths in ``__post_init__``, so they normally exist.
        if not source.exists() and not isinstance(
            bind, (RWBindConfig, OverlayBindConfig)
        ):
            return []

        target = bind.target if bind.target is not None else bind.source
        return [
            MountClaim(
                target=_norm_target(target),
                kind=_kind_for_bind(bind),
                source=_source_for_bind(bind),
                origin=origin,
            )
        ]

    if isinstance(bind, tuple):
        return list(claims_from_bwrap_args(bind, origin))

    return []


def claims_from_bwrap_args(
    args: Sequence[str],
    origin: str,
) -> Iterator[MountClaim]:
    """Parse mount-related flags from a flat bwrap argv fragment."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _BIND_FLAG_KIND and i + 2 < len(args):
            yield MountClaim(
                target=_norm_target(args[i + 2]),
                kind=_BIND_FLAG_KIND[arg],
                source=os.fspath(args[i + 1]),
                origin=origin,
            )
            i += 3
            continue
        if arg == "--symlink" and i + 2 < len(args):
            yield MountClaim(
                target=_norm_target(args[i + 2]),
                kind="symlink",
                source=os.fspath(args[i + 1]),
                origin=origin,
            )
            i += 3
            continue
        if arg == "--tmpfs" and i + 1 < len(args):
            yield MountClaim(
                target=_norm_target(args[i + 1]),
                kind="tmpfs",
                source=None,
                origin=origin,
            )
            i += 2
            continue
        if arg == "--dir" and i + 1 < len(args):
            yield MountClaim(
                target=_norm_target(args[i + 1]),
                kind="dir",
                source=None,
                origin=origin,
            )
            i += 2
            continue
        if arg in {"--proc", "--dev"} and i + 1 < len(args):
            yield MountClaim(
                target=_norm_target(args[i + 1]),
                kind=arg.lstrip("-"),
                source=None,
                origin=origin,
            )
            i += 2
            continue
        if arg == "--overlay-src" and i + 1 < len(args):
            # Handled with following --tmp-overlay / --overlay; skip source alone.
            i += 2
            continue
        if arg == "--tmp-overlay" and i + 1 < len(args):
            yield MountClaim(
                target=_norm_target(args[i + 1]),
                kind="tmp-overlay",
                source=None,
                origin=origin,
            )
            i += 2
            continue
        if arg == "--overlay" and i + 3 < len(args):
            upper, _work, target = args[i + 1], args[i + 2], args[i + 3]
            yield MountClaim(
                target=_norm_target(target),
                kind="overlay",
                source=f"(upper={upper})",
                origin=origin,
            )
            i += 4
            continue
        i += 1


def env_claims_from_bwrap_args(
    args: Sequence[str],
    origin: str,
) -> Iterator[EnvClaim]:
    """Parse ``--setenv`` assignments from a flat bwrap argv fragment."""
    i = 0
    while i < len(args):
        if args[i] == "--setenv" and i + 2 < len(args):
            yield EnvClaim(name=args[i + 1], value=args[i + 2], origin=origin)
            i += 3
            continue
        i += 1


def iter_bind_claims(
    config: Mapping,
    enabled: Mapping[str, bool],
) -> Iterator[MountClaim]:
    """Yield mount claims for base + enabled features + config binds."""
    from buddelkiste.features import base_binds

    policy = bind_symlink_policy(config)

    def _claims(bind: object, origin: str) -> list[MountClaim]:
        try:
            rewritten = apply_one_bind_symlink(bind, policy)
        except (TypeError, ValueError) as exc:
            raise click.ClickException(str(exc)) from exc
        claims: list[MountClaim] = []
        for piece in rewritten:
            claims.extend(claims_from_bind(piece, origin))
        return claims

    registry = load_feature_registry(dict(config))
    for bind in base_binds():
        yield from _claims(bind, "base")
    for name in enabled_feature_names(dict(enabled), registry):
        for bind in registry[name].binds():
            yield from _claims(bind, f"feature {name!r}")
    for index, bind_params in enumerate(config.get("binds", ())):
        for bind in binds_from_spec(dict(bind_params), where=f"binds[{index}]"):
            yield from _claims(bind, f"config binds[{index}]")


def iter_env_claims(
    config: Mapping,
    enabled: Mapping[str, bool],
    *,
    environ: Mapping[str, str] | None = None,
) -> Iterator[EnvClaim]:
    """Yield env claims that ``get_env_args`` would forward or set."""
    envmap = os.environ if environ is None else environ
    registry = load_feature_registry(dict(config))

    for var_name in BASE_ENV_VARS:
        value = envmap.get(var_name)
        if value is not None:
            yield EnvClaim(var_name, value, "base (host environment)")

    for name in enabled_feature_names(dict(enabled), registry):
        for var_name in registry[name].env_vars:
            value = envmap.get(var_name)
            if value is not None:
                yield EnvClaim(
                    var_name,
                    value,
                    f"feature {name!r} (host environment)",
                )

    for index, cfg in enumerate(config.get("envvars", ())):
        var_name = str(cfg["name"])
        if "value" in cfg and cfg["value"] is not None:
            yield EnvClaim(
                var_name,
                str(cfg["value"]),
                f"config envvars[{index}] (explicit value)",
            )
        else:
            value = envmap.get(var_name)
            if value is not None:
                yield EnvClaim(
                    var_name,
                    value,
                    f"config envvars[{index}] (host environment)",
                )


def check_feature_mutex(
    enabled: Mapping[str, bool],
    config: Mapping | None = None,
) -> list[str]:
    """Return human-readable errors for incompatible enabled features."""
    registry = load_feature_registry(dict(config or {}))
    names = enabled_feature_names(dict(enabled), registry)
    active = set(names)
    errors: list[str] = []
    seen_pairs: set[tuple[str, str]] = set()

    for name in names:
        for other in registry[name].conflicts_with:
            if other not in active:
                continue
            pair = (name, other) if name < other else (other, name)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            errors.append(
                f"Features {name!r} and {other!r} cannot be enabled together. "
                f"Disable one with --no-feature {name} or --no-feature {other}."
            )
    return errors


def find_mount_conflicts(
    claims: Iterable[MountClaim],
    *,
    bind_conflicts: str = DEFAULT_BIND_CONFLICTS,
) -> list[str]:
    """Return errors for the same target claimed incompatibly.

    When ``bind_conflicts`` is ``stronger`` or ``weaker``, a same-source
    ro vs rw pair is treated as resolved rather than as an error.
    """
    policy = normalize_bind_conflicts(bind_conflicts)
    by_target: dict[str, list[MountClaim]] = defaultdict(list)
    for claim in claims:
        by_target[claim.target].append(claim)

    errors: list[str] = []
    for target, group in sorted(by_target.items()):
        identities = {claim.identity for claim in group}
        if len(identities) <= 1:
            continue
        if policy != "error" and _resolvable_ro_rw_conflict(group):
            continue
        lines = [f"Mount target {target}:"]
        # Deduplicate identical claims when listing.
        seen: set[tuple[str, str | None, str]] = set()
        for claim in group:
            key = (*claim.identity, claim.origin)
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"  - {claim.describe()}")
        errors.append("\n".join(lines))
    return errors


def find_env_conflicts(claims: Iterable[EnvClaim]) -> list[str]:
    """Return errors for the same variable set to different values."""
    by_name: dict[str, list[EnvClaim]] = defaultdict(list)
    for claim in claims:
        by_name[claim.name].append(claim)

    errors: list[str] = []
    for name, group in sorted(by_name.items()):
        values = {claim.value for claim in group}
        if len(values) <= 1:
            continue
        lines = [f"Environment variable {name}:"]
        seen: set[tuple[str, str]] = set()
        for claim in group:
            key = (claim.value, claim.origin)
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"  - {claim.describe()}")
        errors.append("\n".join(lines))
    return errors


def check_launch_conflicts(
    *,
    enabled: Mapping[str, bool],
    config: Mapping,
    binds: Sequence[object] = (),
    setup_parts: Sequence[tuple[str, Sequence[str]]] = (),
    environ: Mapping[str, str] | None = None,
) -> None:
    """Raise ``ClickException`` if features, mounts, or env assignments conflict.

    Mount and env claims are derived from ``config`` / ``enabled`` with feature
    provenance. ``binds`` may include extras (e.g. cwd whitelist) not present in
    config. Setup fragments are merged when given.
    """
    errors = check_feature_mutex(enabled, config)
    policy = bind_conflict_policy(config)

    mount_claims = list(iter_bind_claims(config, enabled))
    known_mounts = {(c.target, c.identity) for c in mount_claims}
    for bind in binds:
        for claim in claims_from_bind(bind, "working-directory / extra bind"):
            key = (claim.target, claim.identity)
            if key not in known_mounts:
                mount_claims.append(claim)
                known_mounts.add(key)

    for name, part in setup_parts:
        mount_claims.extend(claims_from_bwrap_args(part, f"feature {name!r} setup"))
    errors.extend(find_mount_conflicts(mount_claims, bind_conflicts=policy))

    env_claims = list(iter_env_claims(config, enabled, environ=environ))
    for name, part in setup_parts:
        env_claims.extend(
            env_claims_from_bwrap_args(part, f"feature {name!r} setup")
        )
    errors.extend(find_env_conflicts(env_claims))

    if errors:
        body = "\n\n".join(errors)
        raise click.ClickException(
            "Sandbox configuration conflicts detected; refusing to start.\n\n"
            f"{body}"
        )
