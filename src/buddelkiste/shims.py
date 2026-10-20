"""PATH shims that wrap configured executables with ``bk run``."""

from __future__ import annotations

import os
import shlex
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import click

SHIM_VERSION = 1
SHIM_MARKER_PREFIX = "# buddelkiste-shim:"
SHIM_MARKER = f"{SHIM_MARKER_PREFIX}{SHIM_VERSION}"

ENV_VERSION = 1
ENV_MARKER_PREFIX = "# buddelkiste-shims-env:"
ENV_MARKER = f"{ENV_MARKER_PREFIX}{ENV_VERSION}"

HOOK_BEGIN = "# buddelkiste-shims-hook"
HOOK_END = "# end buddelkiste-shims-hook"
RC_FILENAMES = (".bashrc", ".zshrc")


def user_home(*, environ: Mapping[str, str] | None = None) -> Path:
    """Return the user home directory from ``HOME`` or :func:`Path.home`."""
    env = environ if environ is not None else os.environ
    return Path(env.get("HOME") or str(Path.home()))


def xdg_data_home(*, environ: Mapping[str, str] | None = None) -> Path:
    """Return the user data directory (``XDG_DATA_HOME`` or ``~/.local/share``)."""
    env = environ if environ is not None else os.environ
    override = env.get("XDG_DATA_HOME")
    if override:
        return Path(override).expanduser()
    return user_home(environ=env) / ".local" / "share"


def shim_dir(*, environ: Mapping[str, str] | None = None) -> Path:
    """Directory that holds installed PATH shims."""
    return xdg_data_home(environ=environ) / "buddelkiste" / "shims"


def shim_env_path(*, environ: Mapping[str, str] | None = None) -> Path:
    """Managed shell snippet sourced from interactive rc files."""
    return xdg_data_home(environ=environ) / "buddelkiste" / "shims.sh"


def home_relative_shell_path(path: Path, *, home: Path) -> str:
    """Quote ``path`` for a shell, preferring ``$HOME`` when it lives under home.

    The path is resolved so the include is stable, but the home prefix is left
    as ``$HOME`` so the same rc snippet works for different users.
    """
    try:
        resolved = path.expanduser().resolve()
        home_resolved = home.expanduser().resolve()
    except OSError:
        resolved = path.expanduser()
        home_resolved = home.expanduser()
    try:
        rel = resolved.relative_to(home_resolved)
    except ValueError:
        return shlex.quote(str(resolved))
    return '"$HOME/' + rel.as_posix().replace('"', '\\"') + '"'


def global_shims_enabled(config: dict) -> bool:
    """Return the global ``shims`` toggle (default ``True``)."""
    if "shims" not in config:
        return True
    value = config["shims"]
    if not isinstance(value, bool):
        raise click.ClickException("config 'shims' must be a boolean")
    return value


def executable_shim_enabled(config: dict, entry: dict | None) -> bool:
    """Whether an executable entry should get a PATH shim.

    Precedence: per-entry ``shim`` boolean overrides the global ``shims`` default.
    """
    if isinstance(entry, dict) and "shim" in entry:
        value = entry["shim"]
        if not isinstance(value, bool):
            raise click.ClickException("executables.*.shim must be a boolean")
        return value
    return global_shims_enabled(config)


def shim_decisions_from_config(config: dict) -> dict[str, bool]:
    """Map shim basenames to whether they should be installed.

    Duplicate basenames keep the first decision encountered.
    """
    executables = config.get("executables")
    if not isinstance(executables, dict):
        return {}

    decisions: dict[str, bool] = {}
    for key, entry in executables.items():
        name = Path(str(key)).name
        if not name or name in {".", ".."} or name in decisions:
            continue
        table = entry if isinstance(entry, dict) else None
        decisions[name] = executable_shim_enabled(config, table)
    return decisions


def shim_names_from_config(config: dict) -> list[str]:
    """Basenames that should have PATH shims, stable and de-duplicated."""
    return [name for name, enabled in shim_decisions_from_config(config).items() if enabled]


def render_shim() -> str:
    """Return the shell script body for a buddelkiste PATH shim."""
    return f"""\
#!/bin/sh
{SHIM_MARKER}
# Managed by buddelkiste (`bk shims install`). Do not edit.
set -eu
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
name=$(basename -- "$0")
bk=$(command -v bk) || {{
  printf '%s\\n' "buddelkiste: bk not found on PATH" >&2
  exit 127
}}
# Walk PATH (skipping this shim directory) for a real executable file.
# Avoid `command -v`, which may report shell builtins.
real=
old_ifs=$IFS
IFS=:
for p in $PATH; do
  [ -n "$p" ] || continue
  [ "$p" = "$dir" ] && continue
  candidate=$p/$name
  if [ -f "$candidate" ] && [ -x "$candidate" ]; then
    real=$candidate
    break
  fi
done
IFS=$old_ifs
[ -n "$real" ] || {{
  printf '%s\\n' "buddelkiste: $name not found on PATH outside $dir" >&2
  exit 127
}}
exec "$bk" run "$real" "$@"
"""


def render_shim_env(*, shim_directory: Path, home: Path) -> str:
    """Return the POSIX snippet that prepends the shim dir and runs a quiet check."""
    quoted = home_relative_shell_path(shim_directory, home=home)
    return (
        f"{ENV_MARKER}\n"
        "# Managed by buddelkiste (`bk shims install`). Do not edit.\n"
        f"_bk_shims={quoted}\n"
        'case ":${PATH}:" in\n'
        '  *":${_bk_shims}:"*) ;;\n'
        '  *) PATH="${_bk_shims}${PATH:+:${PATH}}" ;;\n'
        "esac\n"
        "export PATH\n"
        "unset _bk_shims\n"
        "\n"
        "case $- in\n"
        "  *i*)\n"
        "    if command -v bk >/dev/null 2>&1; then\n"
        "      bk shims check --quiet || true\n"
        "    fi\n"
        "    ;;\n"
        "esac\n"
    )


def render_rc_include(env_path: Path, *, home: Path) -> str:
    """Return the marked rc block that sources the managed snippet."""
    quoted = home_relative_shell_path(env_path, home=home)
    return (
        f"{HOOK_BEGIN}\n"
        "# Managed by buddelkiste (`bk shims install`). Do not edit this block.\n"
        f"if [ -r {quoted} ]; then\n"
        f"  . {quoted}\n"
        "fi\n"
        f"{HOOK_END}\n"
    )


def is_our_shim(path: Path) -> bool:
    """True if ``path`` is a buddelkiste-managed shim (any marker version)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    for line in text.splitlines()[:8]:
        if line.startswith(SHIM_MARKER_PREFIX):
            return True
    return False


def _path_entries(path_value: str | None = None) -> list[Path]:
    raw = path_value if path_value is not None else os.environ.get("PATH", "")
    return [Path(part) for part in raw.split(":") if part]


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return left == right


def _is_executable(path: Path) -> bool:
    try:
        return path.is_file() and os.access(path, os.X_OK)
    except OSError:
        return False


def upsert_rc_hook(path: Path, block: str) -> str:
    """Insert or replace the marked hook block in an existing rc file."""
    text = path.read_text(encoding="utf-8")
    if not block.endswith("\n"):
        block += "\n"
    start = text.find(HOOK_BEGIN)
    if start != -1:
        end = text.find(HOOK_END, start)
        if end != -1:
            end += len(HOOK_END)
            if end < len(text) and text[end] == "\n":
                end += 1
            new_text = text[:start] + block + text[end:]
        else:
            new_text = text[:start] + block
    else:
        prefix = text
        if prefix and not prefix.endswith("\n"):
            prefix += "\n"
        new_text = prefix + block
    if new_text == text:
        return "unchanged"
    path.write_text(new_text, encoding="utf-8")
    return "updated"


@dataclass(frozen=True)
class ShimInstallResult:
    name: str
    path: Path
    action: str  # created | updated | unchanged | skipped | removed


def install_shims(
    names: list[str],
    *,
    bin_dir: Path | None = None,
    remove: list[str] | None = None,
) -> list[ShimInstallResult]:
    """Create or refresh shims for ``names`` under the application shim directory.

    Existing non-shim files are left alone (``skipped``). Our own shims are
    rewritten when their contents differ from the current template. Names in
    ``remove`` delete a managed shim if present.
    """
    target_dir = bin_dir if bin_dir is not None else shim_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    body = render_shim()
    results: list[ShimInstallResult] = []

    for name in remove or ():
        path = target_dir / name
        if path.exists() and is_our_shim(path):
            path.unlink()
            results.append(ShimInstallResult(name, path, "removed"))
        elif path.exists():
            results.append(ShimInstallResult(name, path, "skipped"))

    for name in names:
        path = target_dir / name
        if path.exists() and not is_our_shim(path):
            results.append(ShimInstallResult(name, path, "skipped"))
            continue

        existed = path.exists()
        previous = path.read_text(encoding="utf-8") if existed else None
        if previous == body:
            results.append(ShimInstallResult(name, path, "unchanged"))
            continue

        path.write_text(body, encoding="utf-8")
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        action = "updated" if existed else "created"
        results.append(ShimInstallResult(name, path, action))

    return results


def install_shims_from_config(
    config: dict,
    *,
    bin_dir: Path | None = None,
) -> list[ShimInstallResult]:
    """Install/update enabled shims and remove managed shims that are disabled."""
    decisions = shim_decisions_from_config(config)
    enabled = [name for name, on in decisions.items() if on]
    disabled = [name for name, on in decisions.items() if not on]
    return install_shims(enabled, bin_dir=bin_dir, remove=disabled)


def install_shim_hook(
    *,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> list[ShimInstallResult]:
    """Write the managed env snippet and include it from existing bash/zsh rc files."""
    env = environ if environ is not None else os.environ
    home_path = home if home is not None else user_home(environ=env)
    results: list[ShimInstallResult] = []

    env_path = shim_env_path(environ=env)
    env_path.parent.mkdir(parents=True, exist_ok=True)
    body = render_shim_env(shim_directory=shim_dir(environ=env), home=home_path)
    existed = env_path.exists()
    previous = env_path.read_text(encoding="utf-8") if existed else None
    if previous == body:
        results.append(ShimInstallResult(env_path.name, env_path, "unchanged"))
    else:
        env_path.write_text(body, encoding="utf-8")
        action = "updated" if existed else "created"
        results.append(ShimInstallResult(env_path.name, env_path, action))

    block = render_rc_include(env_path, home=home_path)
    for name in RC_FILENAMES:
        rc_path = home_path / name
        if not rc_path.is_file():
            continue
        action = upsert_rc_hook(rc_path, block)
        results.append(ShimInstallResult(name, rc_path, action))
    return results


@dataclass(frozen=True)
class ShimCheckIssue:
    name: str
    message: str


def check_shims(
    names: list[str],
    *,
    bin_dir: Path | None = None,
    path_value: str | None = None,
) -> list[ShimCheckIssue]:
    """Return issues where a non-shim executable would win over our shim on PATH."""
    target_dir = bin_dir if bin_dir is not None else shim_dir()
    path_dirs = _path_entries(path_value)
    issues: list[ShimCheckIssue] = []

    bin_on_path = any(_same_path(entry, target_dir) for entry in path_dirs)
    if names and not bin_on_path:
        issues.append(
            ShimCheckIssue(
                "*",
                f"shim directory {target_dir} is not on PATH; "
                "installed shims will not intercept commands",
            )
        )

    for name in names:
        shim_path = target_dir / name
        first: Path | None = None
        for directory in path_dirs:
            candidate = directory / name
            if not _is_executable(candidate):
                continue
            first = candidate
            break

        if first is None:
            if shim_path.exists() and is_our_shim(shim_path):
                issues.append(
                    ShimCheckIssue(
                        name,
                        f"shim exists at {shim_path} but is not reachable via PATH",
                    )
                )
            else:
                issues.append(
                    ShimCheckIssue(
                        name,
                        f"no shim installed for {name!r} "
                        f"(expected {shim_path}); run `bk shims install`",
                    )
                )
            continue

        if is_our_shim(first) and _same_path(first, shim_path):
            continue

        if is_our_shim(first):
            # Another buddelkiste shim earlier on PATH — unusual but safe.
            continue

        issues.append(
            ShimCheckIssue(
                name,
                f"{first} is found on PATH before the buddelkiste shim "
                f"at {shim_path}; calls to {name!r} will bypass the sandbox",
            )
        )

    return issues
