"""Interactive prompts for project registration (BeauPy on Rich)."""

from __future__ import annotations

from beaupy import Config, select, select_multiple
from rich.console import Console

from buddelkiste.features import (
    feature_names,
    load_feature_registry,
    lookup_executable_config,
)

_ACCESS_CHOICES: tuple[tuple[str, str], ...] = (
    ("yes", "this run only"),
    ("always", "persist as a [[projects]] entry"),
    ("no", "abort"),
)
_ACCESS_NAMES = [name for name, _ in _ACCESS_CHOICES]
_ACCESS_LABELS = dict(_ACCESS_CHOICES)


def _config(console: Console | None) -> Config:
    cons = console or Console(stderr=True, highlight=False)
    return Config(console=cons)


def prompt_cwd_access(*, console: Console | None = None) -> str:
    """Ask whether to add the cwd as a project: yes, no, or always."""
    width = max(len(name) for name in _ACCESS_NAMES)
    choice = select(
        _ACCESS_NAMES,
        preprocessor=lambda name: f"{name:<{width}}  [dim]{_ACCESS_LABELS[name]}[/dim]",
        cursor="❯",
        cursor_style="cyan",
        cursor_index=_ACCESS_NAMES.index("no"),
        title="Add it as a project for this run, persist it, or abort?",
        config=_config(console),
    )
    return "no" if choice is None else choice


def _executable_feature_names(config: dict, executable: str | None) -> set[str]:
    """Features the executable config would turn on (list allowlist or true keys)."""
    exec_cfg = lookup_executable_config(config, executable)
    if exec_cfg is None or "features" not in exec_cfg:
        return set()
    spec = exec_cfg["features"]
    if isinstance(spec, list):
        return {str(name) for name in spec}
    if isinstance(spec, dict):
        return {str(name) for name, value in spec.items() if value}
    return set()


def prompt_project_features(
    config: dict,
    *,
    executable: str | None = None,
    console: Console | None = None,
) -> dict[str, bool]:
    """Ask which extra features to enable for a new project.

    Features the current executable already enables are omitted from the list.
    """
    registry = load_feature_registry(config)
    already = _executable_feature_names(config, executable)
    names = [
        name
        for name in feature_names(registry)
        if name != "user" and name not in already
    ]
    if not names:
        return {}
    width = max(len(name) for name in names)
    selected = select_multiple(
        names,
        preprocessor=lambda name: (
            f"{name:<{width}}  [dim]{registry[name].description}[/dim]"
        ),
        tick_character="✓",
        tick_style="green",
        cursor_style="cyan",
        title="Features to enable for this project (none extra if you confirm empty):",
        filterable=True,
        config=_config(console),
    )
    return {name: True for name in (selected or [])}
