"""Interactive prompts for project registration (Rich, no alternate screen)."""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Prompt

from buddelkiste.features import feature_names, load_feature_registry


def prompt_cwd_access(*, console: Console | None = None) -> str:
    """Ask whether to add the cwd as a project: yes, no, or always."""
    cons = console or Console(stderr=True)
    return Prompt.ask(
        "Add it as a project for this run [yes], persist it [always], or abort [no]?",
        choices=["yes", "no", "always"],
        default="no",
        console=cons,
        show_choices=True,
    )


def prompt_project_features(
    config: dict,
    *,
    console: Console | None = None,
) -> dict[str, bool]:
    """Ask which features to enable for a new project.

    Prints a compact name/description list and reads one line of space- or
    comma-separated names. Empty input enables nothing extra.
    """
    cons = console or Console(stderr=True)
    registry = load_feature_registry(config)
    names = [name for name in feature_names(registry) if name != "user"]
    cons.print(
        "Features to enable for this project "
        "(space- or comma-separated names, empty for none):"
    )
    width = max((len(name) for name in names), default=0)
    for name in names:
        cons.print(f"  {name:<{width}}  [dim]{registry[name].description}[/dim]")

    while True:
        raw = Prompt.ask("Features", default="", console=cons, show_default=False)
        selected = [part for part in raw.replace(",", " ").split() if part]
        unknown = [name for name in selected if name not in registry]
        if unknown:
            cons.print(
                f"Unknown feature(s): {', '.join(unknown)}. "
                f"Expected one of: {', '.join(feature_names(registry))}"
            )
            continue
        return {name: True for name in selected}
