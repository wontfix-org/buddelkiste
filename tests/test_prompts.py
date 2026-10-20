from __future__ import annotations

from io import StringIO

from rich.console import Console

from buddelkiste.prompts import prompt_cwd_access, prompt_project_features


def test_prompt_cwd_access_returns_choice(monkeypatch) -> None:
    monkeypatch.setattr("buddelkiste.prompts.Prompt.ask", lambda *a, **k: "always")
    assert prompt_cwd_access(console=Console(file=StringIO())) == "always"


def test_prompt_project_features_parses_names(monkeypatch) -> None:
    monkeypatch.setattr("buddelkiste.prompts.Prompt.ask", lambda *a, **k: "python, rust")
    selected = prompt_project_features({}, console=Console(file=StringIO()))
    assert selected == {"python": True, "rust": True}


def test_prompt_project_features_empty(monkeypatch) -> None:
    monkeypatch.setattr("buddelkiste.prompts.Prompt.ask", lambda *a, **k: "")
    assert prompt_project_features({}, console=Console(file=StringIO())) == {}
