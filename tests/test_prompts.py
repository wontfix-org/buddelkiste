from __future__ import annotations

from io import StringIO

from rich.console import Console

from buddelkiste.prompts import prompt_cwd_access, prompt_project_features


def _console() -> Console:
    return Console(file=StringIO())


def test_prompt_cwd_access_returns_choice(monkeypatch) -> None:
    monkeypatch.setattr("buddelkiste.prompts.select", lambda options, **k: "always")
    assert prompt_cwd_access(console=_console()) == "always"


def test_prompt_cwd_access_escape_is_no(monkeypatch) -> None:
    monkeypatch.setattr("buddelkiste.prompts.select", lambda options, **k: None)
    assert prompt_cwd_access(console=_console()) == "no"


def test_prompt_cwd_access_defaults_cursor_to_no(monkeypatch) -> None:
    seen: dict = {}

    def fake_select(options, **kwargs):
        seen["options"] = options
        seen.update(kwargs)
        return "no"

    monkeypatch.setattr("buddelkiste.prompts.select", fake_select)
    assert prompt_cwd_access(console=_console()) == "no"
    assert seen["options"] == ["yes", "always", "no"]
    assert seen["cursor_index"] == 2


def test_prompt_project_features_maps_names(monkeypatch) -> None:
    seen: dict = {}

    def fake_select_multiple(options, **kwargs):
        seen["options"] = options
        seen.update(kwargs)
        return ["python", "rust"]

    monkeypatch.setattr("buddelkiste.prompts.select_multiple", fake_select_multiple)
    selected = prompt_project_features({}, console=_console())
    assert selected == {"python": True, "rust": True}
    assert "python" in seen["options"]
    assert "rust" in seen["options"]
    assert "user" not in seen["options"]
    assert seen["filterable"] is True


def test_prompt_project_features_empty(monkeypatch) -> None:
    monkeypatch.setattr("buddelkiste.prompts.select_multiple", lambda options, **k: [])
    assert prompt_project_features({}, console=_console()) == {}
