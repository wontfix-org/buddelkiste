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


def test_prompt_project_features_omits_executable_allowlist(monkeypatch) -> None:
    seen: dict = {}

    def fake_select_multiple(options, **kwargs):
        seen["options"] = options
        return []

    monkeypatch.setattr("buddelkiste.prompts.select_multiple", fake_select_multiple)
    config = {
        "executables": {
            "python": {"features": ["python", "git"]},
        }
    }
    assert prompt_project_features(
        config, executable="/usr/bin/python", console=_console()
    ) == {}
    assert "python" not in seen["options"]
    assert "git" not in seen["options"]
    assert "rust" in seen["options"]
    assert "user" not in seen["options"]


def test_prompt_project_features_omits_executable_table_trues(monkeypatch) -> None:
    seen: dict = {}

    def fake_select_multiple(options, **kwargs):
        seen["options"] = options
        return ["ssh"]

    monkeypatch.setattr("buddelkiste.prompts.select_multiple", fake_select_multiple)
    config = {
        "executables": {
            "cursor-agent": {"features": {"cursor": True, "rust": False}},
        }
    }
    selected = prompt_project_features(
        config, executable="cursor-agent", console=_console()
    )
    assert selected == {"ssh": True}
    assert "cursor" not in seen["options"]
    assert "rust" in seen["options"]


def test_prompt_project_features_omits_cli_enable_and_disable(monkeypatch) -> None:
    seen: dict = {}

    def fake_select_multiple(options, **kwargs):
        seen["options"] = options
        return ["git"]

    monkeypatch.setattr("buddelkiste.prompts.select_multiple", fake_select_multiple)
    selected = prompt_project_features(
        {},
        executable="cursor-agent",
        enable=("python", "ssh"),
        disable=("rust",),
        console=_console(),
    )
    assert selected == {"git": True}
    assert "python" not in seen["options"]
    assert "ssh" not in seen["options"]
    assert "rust" not in seen["options"]
    assert "git" in seen["options"]
    assert "cursor" in seen["options"]


def test_prompt_project_features_cli_and_executable_together(monkeypatch) -> None:
    seen: dict = {}

    def fake_select_multiple(options, **kwargs):
        seen["options"] = options
        return []

    monkeypatch.setattr("buddelkiste.prompts.select_multiple", fake_select_multiple)
    config = {
        "executables": {
            "python": {"features": ["python", "git"]},
        }
    }
    prompt_project_features(
        config,
        executable="/usr/bin/python",
        enable=("ssh",),
        disable=("rust", "node"),
        console=_console(),
    )
    assert "python" not in seen["options"]
    assert "git" not in seen["options"]
    assert "ssh" not in seen["options"]
    assert "rust" not in seen["options"]
    assert "node" not in seen["options"]
    assert "cursor" in seen["options"]


def test_prompt_project_features_unknown_executable_keeps_catalog(
    monkeypatch,
) -> None:
    seen: dict = {}

    def fake_select_multiple(options, **kwargs):
        seen["options"] = options
        return []

    monkeypatch.setattr("buddelkiste.prompts.select_multiple", fake_select_multiple)
    prompt_project_features({}, executable="python", console=_console())
    assert "python" in seen["options"]
    assert "git" in seen["options"]
