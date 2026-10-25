"""Bubblewrap bind-mount helpers."""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("buddelkiste")


def force_rmtree(path: Path | str) -> None:
    """Remove a directory tree, including overlayfs work dirs left mode ``000``.

    After ``bwrap --overlay`` exits, the kernel work subdirectory is often
    ``d---------``, which makes a plain ``shutil.rmtree`` / pytest ``rm_rf``
    fail with ``ENOTEMPTY`` / ``EACCES`` and leave ``garbage-*`` warnings.
    """
    root = Path(path)
    if not root.exists():
        return

    def _unlock_and_remove(current: Path) -> None:
        try:
            os.chmod(current, 0o700)
        except OSError:
            pass
        if current.is_dir() and not current.is_symlink():
            try:
                children = list(current.iterdir())
            except OSError:
                children = []
            for child in children:
                _unlock_and_remove(child)
            try:
                current.rmdir()
            except OSError:
                shutil.rmtree(current, ignore_errors=True)
        else:
            try:
                current.unlink()
            except OSError:
                pass

    _unlock_and_remove(root)


BIND_SYMLINK_POLICIES = ("follow", "preserve", "error")
DEFAULT_BIND_SYMLINKS = "follow"


def normalize_bind_symlinks(raw: object, *, where: str = "bind_symlinks") -> str:
    """Return ``follow``, ``preserve``, or ``error``."""
    allowed = ", ".join(repr(item) for item in BIND_SYMLINK_POLICIES)
    if not isinstance(raw, str):
        raise TypeError(f"{where} must be {allowed} (got {raw!r})")
    value = raw.strip().lower()
    if value not in BIND_SYMLINK_POLICIES:
        raise ValueError(f"{where} must be {allowed} (got {raw!r})")
    return value


def is_file_symlink(path: Path | str) -> bool:
    """True for a symbolic link that is not a directory (including dangling)."""
    current = Path(path)
    return current.is_symlink() and not current.is_dir()


@dataclass
class BasicBindConfig:
    source: Path | str
    target: Path | str | None = None
    flag: str | None = None
    symlink: str | None = field(default=None, kw_only=True)
    origin: str | None = field(default=None, kw_only=True)

    def __post_init__(self):
        self.source = os.fspath(self.source)
        if self.target is None:
            self.target = self.source
        else:
            self.target = os.fspath(self.target)
        if self.symlink is not None:
            self.symlink = normalize_bind_symlinks(self.symlink, where="symlink")

    def __iter__(self) -> Iterator[str]:
        if self.flag is None:
            raise TypeError(f"{type(self).__name__} requires a bind flag")
        source = os.fspath(self.source)
        target = os.fspath(self.target) if self.target is not None else source
        if Path(source).exists():
            yield from (self.flag, source, target)

    def covers_path(self, path: Path) -> bool:
        source = Path(self.source)
        if not source.exists():
            return False
        path = path.resolve()
        source = source.resolve()
        return path == source or path in source.parents or source in path.parents


@dataclass(frozen=True)
class BindSymlinkEvent:
    """A follow / preserve / skip decision from :func:`apply_bind_symlinks`."""

    action: str
    source: str
    dest: str
    referent: str | None = None
    covered_by: str | None = None
    origin: str | None = None

    def describe(self) -> str:
        where = f" ({self.origin})" if self.origin else ""
        if self.action == "follow":
            target = self.referent or self.dest
            return f"bind_symlinks follow{where}: {self.source} -> {target}"
        if self.action == "preserve":
            return f"bind_symlinks preserve{where}: {self.source}"
        if self.action == "skip-covered":
            shown = self.referent or self.dest
            cover = self.covered_by or "another mount"
            return (
                f"bind_symlinks skip{where}: {self.source} -> {shown} "
                f"(covered by {cover})"
            )
        return f"bind_symlinks {self.action}{where}: {self.source}"


@dataclass
class ROBindConfig(BasicBindConfig):
    """Read only binds"""

    flag: str = "--ro-bind"


@dataclass
class RWBindConfig(BasicBindConfig):
    """Read + write binds"""

    flag: str = "--bind"

    def __post_init__(self):
        super().__post_init__()
        srcpath = Path(self.source)
        if not srcpath.exists() and not srcpath.is_symlink():
            srcpath.mkdir(parents=True)


@dataclass
class DevBindConfig(BasicBindConfig):
    flag: str = "--dev-bind"


@dataclass
class TmpOverlayBindConfig(BasicBindConfig):
    """Read from source; sandbox writes go to an ephemeral tmpfs overlay."""

    def __iter__(self) -> Iterator[str]:
        source = os.fspath(self.source)
        target = os.fspath(self.target) if self.target is not None else source
        if Path(source).exists():
            yield from ("--overlay-src", source, "--tmp-overlay", target)


@dataclass(kw_only=True)
class OverlayBindConfig(BasicBindConfig):
    """Read from source; sandbox writes persist in a host upper directory."""

    upper: Path | str
    work: Path | str | None = None

    def __post_init__(self):
        super().__post_init__()
        upper_path = Path(os.fspath(self.upper))
        upper_path.mkdir(parents=True, exist_ok=True)
        self.upper = os.fspath(upper_path)

        if self.work is None:
            work_path = upper_path.parent / f".{upper_path.name}.work"
        else:
            work_path = Path(os.fspath(self.work))
        if work_path.exists():
            force_rmtree(work_path)
        work_path.mkdir(parents=True)
        self.work = os.fspath(work_path)

    def __iter__(self) -> Iterator[str]:
        source = os.fspath(self.source)
        target = os.fspath(self.target) if self.target is not None else source
        work = self.work
        if work is None:
            raise TypeError("OverlayBindConfig.work was not initialized")
        if Path(source).exists():
            yield from (
                "--overlay-src",
                source,
                "--overlay",
                os.fspath(self.upper),
                os.fspath(work),
                target,
            )


@dataclass
class SymlinkConfig:
    """Recreate a host symbolic link inside the sandbox with ``--symlink``."""

    source: str
    target: Path | str

    def __post_init__(self):
        self.source = os.fspath(self.source)
        self.target = os.fspath(self.target)

    def __iter__(self) -> Iterator[str]:
        yield from ("--symlink", self.source, os.fspath(self.target))


@dataclass
class Tmpfs:
    target: Path | str

    def __iter__(self) -> Iterator[str]:
        return iter(("--tmpfs", os.fspath(self.target)))


def overlay_cache_upper(source: Path | str) -> Path:
    """Return a unique cache upper dir for ``source`` under XDG cache."""
    resolved = str(Path(source).expanduser().resolve())
    digest = hashlib.sha256(resolved.encode()).hexdigest()
    cache_home = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return cache_home / "buddelkiste" / "overlays" / digest


def bind_config(
    source: Path | str,
    target: Path | str | None = None,
    *,
    mode: str = "ro",
):
    """Build a bind config from a mode string.

    Allowed modes: ``ro`` (default), ``rw``, ``tmp-overlay``, ``overlay``
    (persistent upper under the cache dir, named by a hash of the source
    path), or ``overlay:<path>`` for an explicit upper directory.
    """
    if mode == "ro":
        return ROBindConfig(source, target)
    if mode == "rw":
        return RWBindConfig(source, target)
    if mode == "tmp-overlay":
        return TmpOverlayBindConfig(source, target)
    if mode == "overlay":
        return OverlayBindConfig(source, target, upper=overlay_cache_upper(source))

    if mode.startswith("overlay:"):
        upper = mode.removeprefix("overlay:")
        if not upper:
            raise ValueError(
                "Invalid bind mode 'overlay:': use 'overlay' for an automatic "
                "cache upper, or 'overlay:<path>' for an explicit path"
            )
        return OverlayBindConfig(source, target, upper=upper)

    raise ValueError(
        f"Invalid bind mode {mode!r}: expected 'ro', 'rw', "
        "'tmp-overlay', 'overlay', or 'overlay:<path>'"
    )


def _reject_overlay_on_file_symlink(source: Path | str) -> None:
    raise ValueError(f"cannot use overlay mode on symlink file {os.fspath(source)}")


def _same_path(left: Path | str, right: Path | str) -> bool:
    return os.path.normpath(os.fspath(left)) == os.path.normpath(os.fspath(right))


def _clone_bind(
    bind: BasicBindConfig, source: Path | str, target: Path | str
) -> BasicBindConfig:
    if isinstance(bind, OverlayBindConfig):
        return OverlayBindConfig(
            source,
            target,
            upper=bind.upper,
            work=bind.work,
            symlink=bind.symlink,
            origin=bind.origin,
        )
    if isinstance(bind, TmpOverlayBindConfig):
        return TmpOverlayBindConfig(
            source, target, symlink=bind.symlink, origin=bind.origin
        )
    cls = type(bind)
    return cls(source, target, symlink=bind.symlink, origin=bind.origin)


def _mount_covers_dest(mount: Path | str, dest: Path | str, *, descendants: bool) -> bool:
    dest_path = Path(os.path.normpath(os.fspath(dest)))
    mount_path = Path(os.path.normpath(os.fspath(mount)))
    if dest_path == mount_path:
        return True
    if not descendants:
        return False
    try:
        dest_path.relative_to(mount_path)
    except ValueError:
        return False
    return True


def _is_covering_mount(bind: object) -> bool:
    """True for mounts that already provide host or device content at a dest.

    ``--tmpfs`` / ``--dir`` are excluded: they replace the dest with an empty
    tree, so a later host-file bind there is still required. ``--dev`` and
    ``--proc`` already supply their nodes (a later ``--ro-bind /dev/null``
    would make ``/dev/null`` read-only).
    """
    if isinstance(bind, tuple) and len(bind) >= 2:
        return bind[0] in {"--dev", "--proc"}
    if not isinstance(bind, BasicBindConfig):
        return False
    source = Path(os.fspath(bind.source))
    return source.is_dir() and not source.is_symlink()


def _bind_covers_sandbox_path(bind: object, dest: Path | str) -> bool:
    """True when ``bind`` already mounts a sandbox path at or above ``dest``."""
    if isinstance(bind, Tmpfs):
        return _mount_covers_dest(bind.target, dest, descendants=True)
    if isinstance(bind, tuple) and len(bind) >= 2:
        flag = bind[0]
        if flag in {"--dev", "--proc", "--tmpfs", "--dir"}:
            return _mount_covers_dest(bind[1], dest, descendants=True)
        return False
    if not isinstance(bind, BasicBindConfig):
        return False
    mount = bind.target if bind.target is not None else bind.source
    source = Path(os.fspath(bind.source))
    return _mount_covers_dest(mount, dest, descendants=source.is_dir())


def _follow_symlink_bind(bind: BasicBindConfig, path: Path) -> list:
    """Bind the referent; never mount onto the symlink path itself.

    ``--bind`` / ``--ro-bind`` cannot use a symlink as the destination.
    In-place binds therefore mount the resolved path and recreate the
    link with ``--symlink``. A custom dest that is not a symlink still
    receives the referent's content.
    """
    resolved = path.resolve()
    dest = bind.target if bind.target is not None else bind.source
    dest_path = Path(os.fspath(dest))
    in_place = dest_path.is_symlink() or _same_path(dest_path, path)
    pieces: list = []
    if in_place:
        if resolved.exists():
            pieces.append(_clone_bind(bind, resolved, resolved))
        if not _same_path(dest_path, resolved):
            pieces.append(SymlinkConfig(os.readlink(path), dest))
        return pieces
    if resolved.exists():
        pieces.append(_clone_bind(bind, resolved, dest))
    return pieces


def apply_one_bind_symlink(bind: object, policy: str) -> list:
    """Rewrite a symlink bind according to ``follow`` / ``preserve`` / ``error``.

    File symbolic links honor the policy. Directory symbolic links are
    always followed, but still rewritten so bwrap does not mount onto
    the symlink destination. Overlay modes on a file symlink are rejected.
    """
    policy = normalize_bind_symlinks(policy)
    if not isinstance(bind, BasicBindConfig):
        return [bind]
    path = Path(os.fspath(bind.source))
    if not path.is_symlink():
        return [bind]
    local = bind.symlink if bind.symlink is not None else policy
    if is_file_symlink(path):
        if isinstance(bind, (TmpOverlayBindConfig, OverlayBindConfig)):
            _reject_overlay_on_file_symlink(bind.source)
        if local == "error":
            raise ValueError(
                f"bind source {os.fspath(bind.source)} is a symbolic link"
            )
        if local == "preserve":
            dest = bind.target if bind.target is not None else bind.source
            return [SymlinkConfig(os.readlink(path), dest)]
        return _follow_symlink_bind(bind, path)
    return _follow_symlink_bind(bind, path)


def _piece_dest(piece: object) -> str | None:
    if isinstance(piece, SymlinkConfig):
        return os.fspath(piece.target)
    if isinstance(piece, BasicBindConfig):
        dest = piece.target if piece.target is not None else piece.source
        return os.fspath(dest)
    return None


def _describe_cover(bind: object) -> str:
    if isinstance(bind, tuple) and bind:
        return " ".join(os.fspath(part) for part in bind[:2])
    if isinstance(bind, Tmpfs):
        return f"--tmpfs {os.fspath(bind.target)}"
    if isinstance(bind, BasicBindConfig):
        mount = bind.target if bind.target is not None else bind.source
        return os.fspath(mount)
    return str(bind)


def _bind_origin(bind: object) -> str | None:
    return getattr(bind, "origin", None)


def _rewrite_event(bind: object, policy: str) -> BindSymlinkEvent | None:
    if not isinstance(bind, BasicBindConfig):
        return None
    path = Path(os.fspath(bind.source))
    if not path.is_symlink():
        return None
    dest = os.fspath(bind.target if bind.target is not None else bind.source)
    local = bind.symlink if bind.symlink is not None else policy
    if is_file_symlink(path) and local == "preserve":
        return BindSymlinkEvent(
            action="preserve",
            source=os.fspath(bind.source),
            dest=dest,
            origin=bind.origin,
        )
    referent: str | None
    try:
        referent = str(path.resolve())
    except OSError:
        referent = None
    return BindSymlinkEvent(
        action="follow",
        source=os.fspath(bind.source),
        dest=dest,
        referent=referent,
        origin=bind.origin,
    )


def _skip_event(
    bind: object, dest: str, cover: object, *, referent: str | None
) -> BindSymlinkEvent:
    source = (
        os.fspath(bind.source)
        if isinstance(bind, BasicBindConfig)
        else dest
    )
    return BindSymlinkEvent(
        action="skip-covered",
        source=source,
        dest=dest,
        referent=referent,
        covered_by=_describe_cover(cover),
        origin=_bind_origin(bind),
    )


def referent_is_reserved(path: Path | str | None) -> bool:
    """True when ``path`` is under ``/dev`` or ``/proc`` (kernel-provided trees)."""
    if path is None:
        return False
    norm = os.path.normpath(os.fspath(path))
    return norm in {"/dev", "/proc"} or norm.startswith(("/dev/", "/proc/"))


def apply_bind_symlinks(
    binds: Sequence[object], policy: str
) -> tuple[list, list[BindSymlinkEvent]]:
    """Apply :func:`apply_one_bind_symlink` and drop mounts a parent already covers.

    A file bind of a symlink under an already-bound directory (for example
    ``~/.local`` plus a later ``gtk.css`` link) must not emit ``--ro-bind``
    onto that symlink destination. Returns ``(binds, events)``.
    """
    policy = normalize_bind_symlinks(policy)
    covering = [bind for bind in binds if _is_covering_mount(bind)]
    result: list = []
    events: list[BindSymlinkEvent] = []
    for bind in binds:
        rewrite = _rewrite_event(bind, policy)
        if rewrite is not None:
            events.append(rewrite)
        for piece in apply_one_bind_symlink(bind, policy):
            dest = _piece_dest(piece)
            cover = next(
                (
                    item
                    for item in covering
                    if dest is not None and _bind_covers_sandbox_path(item, dest)
                ),
                None,
            )
            if dest is not None and cover is not None:
                # Keep the covering directory bind itself.
                if piece is bind:
                    result.append(piece)
                else:
                    events.append(
                        _skip_event(
                            bind,
                            dest,
                            cover,
                            referent=rewrite.referent if rewrite else None,
                        )
                    )
                continue
            result.append(piece)
    return result, events


def log_bind_symlink_events(events: Sequence[BindSymlinkEvent]) -> None:
    """Log rewrite notes at DEBUG; WARN once if a referent is under /dev or /proc."""
    warned = False
    for event in events:
        log.debug("%s", event.describe())
        if not warned and referent_is_reserved(event.referent):
            log.warning("%s", event.describe())
            warned = True


def set_bind_origin(bind: object, origin: str) -> object:
    """Tag a bind with a human-readable origin when the object supports it."""
    if isinstance(bind, BasicBindConfig):
        bind.origin = origin
    return bind


def format_resolved_bind(bind: object) -> str:
    """Short description of a bind as it will be passed to bwrap."""
    if isinstance(bind, tuple):
        return " ".join(os.fspath(part) for part in bind)
    if isinstance(bind, Tmpfs):
        return f"--tmpfs {os.fspath(bind.target)}"
    if isinstance(bind, SymlinkConfig):
        return f"{bind.source} -> {bind.target} (symlink)"
    if isinstance(bind, OverlayBindConfig):
        dest = bind.target if bind.target is not None else bind.source
        return f"{bind.source} -> {dest} (overlay)"
    if isinstance(bind, TmpOverlayBindConfig):
        dest = bind.target if bind.target is not None else bind.source
        return f"{bind.source} -> {dest} (tmp-overlay)"
    if isinstance(bind, DevBindConfig):
        dest = bind.target if bind.target is not None else bind.source
        if dest == bind.source:
            return f"{bind.source} (dev)"
        return f"{bind.source} -> {dest} (dev)"
    if isinstance(bind, RWBindConfig):
        dest = bind.target if bind.target is not None else bind.source
        if dest == bind.source:
            return f"{bind.source} (rw)"
        return f"{bind.source} -> {dest} (rw)"
    if isinstance(bind, BasicBindConfig):
        dest = bind.target if bind.target is not None else bind.source
        if dest == bind.source:
            return f"{bind.source} (ro)"
        return f"{bind.source} -> {dest} (ro)"
    return str(bind)


def get_bind_args(binds) -> Sequence[str]:
    res = []
    for bind in binds:
        res.extend(bind)
    return res
