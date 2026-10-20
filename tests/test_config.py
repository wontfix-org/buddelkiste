from __future__ import annotations

import tomllib
from pathlib import Path

import click
import pytest

from buddelkiste.cli import (
    RWBindConfig,
    add_bind_to_config,
    add_project_to_config,
    ensure_cwd_project,
    get_binds,
    get_env_args,
    load_config,
    merge_config,
)
from buddelkiste.features import FEATURE_NAMES


def test_load_config_missing_returns_empty(
    tmp_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert load_config() == {}


def test_load_config_reads_toml(
    tmp_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    tmp_config.write_text(
        '[[binds]]\nsource = "/tmp"\nmode = "rw"\n\n'
        '[[envvars]]\nname = "FOO"\nvalue = "bar"\n',
        encoding="utf-8",
    )
    config = load_config()
    assert config["binds"][0]["source"] == "/tmp"
    assert config["binds"][0]["mode"] == "rw"
    assert config["envvars"][0] == {"name": "FOO", "value": "bar"}


def test_merge_config_concatenates_lists_and_overrides_features() -> None:
    base = {
        "features": ["git"],
        "binds": [{"source": "/a", "mode": "ro"}],
        "envvars": [{"name": "A"}],
        "network": {
            "mode": "host",
            "presets": {"corp": ["10.0.0.0/8"]},
        },
        "feature": {"rust": {"env": ["CARGO_HOME"]}},
        "executables": {
            "python": {"features": ["python"], "network": {"mode": "none"}},
        },
    }
    overlay = {
        "features": {"gui": False},
        "binds": [{"source": "/b", "mode": "rw"}],
        "envvars": [{"name": "B"}],
        "network": {
            "mode": "filter",
            "presets": {"labs": ["10.1.0.0/16"]},
        },
        "feature": {"go": {"env": ["GOPATH"]}},
        "executables": {
            "python": {"network": {"allow": ["1.1.1.1/32"]}},
        },
    }
    merged = merge_config(base, overlay)
    assert merged["features"] == {"gui": False}
    assert merged["binds"] == [
        {"source": "/a", "mode": "ro"},
        {"source": "/b", "mode": "rw"},
    ]
    assert merged["envvars"] == [{"name": "A"}, {"name": "B"}]
    assert merged["network"]["mode"] == "filter"
    assert merged["network"]["presets"] == {
        "corp": ["10.0.0.0/8"],
        "labs": ["10.1.0.0/16"],
    }
    assert set(merged["feature"]) == {"rust", "go"}
    assert merged["executables"]["python"]["features"] == ["python"]
    assert merged["executables"]["python"]["network"] == {
        "mode": "none",
        "allow": ["1.1.1.1/32"],
    }


def test_merge_config_concatenates_projects() -> None:
    base = {"projects": [{"path": "/a", "features": {"python": True}}]}
    overlay = {"projects": [{"path": "/b", "features": {"git": True}}]}
    merged = merge_config(base, overlay)
    assert merged["projects"] == [
        {"path": "/a", "features": {"python": True}},
        {"path": "/b", "features": {"git": True}},
    ]


def test_merge_config_merges_dbus_proxy_tables() -> None:
    base = {
        "dbus_proxy": {
            "see": ["org.foo.Bar"],
            "talk": ["org.foo.Baz"],
        },
        "executables": {
            "python": {
                "dbus_proxy": {"talk": ["org.python.App"], "own": ["org.python.Own"]},
            },
        },
    }
    overlay = {
        "dbus_proxy": {"talk": ["org.project.Talk"]},
        "executables": {
            "python": {"dbus_proxy": {"own": ["org.project.Own"]}},
        },
    }
    merged = merge_config(base, overlay)
    assert merged["dbus_proxy"] == {
        "see": ["org.foo.Bar"],
        "talk": ["org.project.Talk"],
    }
    assert merged["executables"]["python"]["dbus_proxy"] == {
        "talk": ["org.python.App"],
        "own": ["org.project.Own"],
    }


def test_load_config_ignores_buddelkiste_toml(
    tmp_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    tmp_config.write_text(
        'features = ["git"]\n[[binds]]\nsource = "/user"\nmode = "ro"\n',
        encoding="utf-8",
    )
    (tmp_path / ".buddelkiste.toml").write_text(
        'features = ["python"]\n[[binds]]\nsource = "/project"\nmode = "rw"\n',
        encoding="utf-8",
    )
    config = load_config()
    assert config["features"] == ["git"]
    assert config["binds"] == [{"source": "/user", "mode": "ro"}]


def test_add_bind_to_config_creates_file(tmp_config: Path, tmp_path: Path) -> None:
    source = tmp_path / "proj"
    source.mkdir()
    add_bind_to_config(source, mode="rw")

    data = tomllib.loads(tmp_config.read_text(encoding="utf-8"))
    assert data["binds"] == [{"source": str(source), "mode": "rw"}]


def test_add_bind_to_config_appends_with_separator(
    tmp_config: Path, tmp_path: Path
) -> None:
    tmp_config.parent.mkdir(parents=True, exist_ok=True)
    tmp_config.write_text('[[envvars]]\nname = "A"\n', encoding="utf-8")

    source = tmp_path / "proj"
    source.mkdir()
    add_bind_to_config(source, mode="ro")

    text = tmp_config.read_text(encoding="utf-8")
    assert text.startswith('[[envvars]]\nname = "A"\n\n[[binds]]\n')
    data = tomllib.loads(text)
    assert data["binds"][0]["mode"] == "ro"


def test_get_env_args_shares_known_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM", "xterm-test")
    monkeypatch.setenv("HOME", "/tmp/bk-home-test")
    monkeypatch.delenv("ASDF_DIR", raising=False)
    # ``user`` is on by default, so TERM is shared. Turning it off drops TERM.
    args = list(get_env_args({}))
    assert ["--setenv", "HOME", "/tmp/bk-home-test"] in [
        args[i : i + 3] for i in range(0, len(args), 3)
    ]
    assert ["--setenv", "TERM", "xterm-test"] in [
        args[i : i + 3] for i in range(0, len(args), 3)
    ]
    assert "ASDF_DIR" not in args

    without_user = list(get_env_args({"features": {"user": False}}))
    assert "TERM" not in without_user


def test_get_env_args_from_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FROM_ENV", "env-value")
    args = list(
        get_env_args(
            {
                "envvars": [
                    {"name": "EXPLICIT", "value": "set"},
                    {"name": "FROM_ENV"},
                ]
            }
        )
    )
    # Find the config-driven entries at the end.
    assert args[-6:] == [
        "--setenv",
        "EXPLICIT",
        "set",
        "--setenv",
        "FROM_ENV",
        "env-value",
    ]


def test_ensure_cwd_covered_by_project_is_noop(
    tmp_path: Path,
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    config = {"projects": [{"path": str(tmp_path)}]}
    result = ensure_cwd_project(config)
    assert result == config


def test_ensure_cwd_noninteractive_errors(
    tmp_path: Path,
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("buddelkiste.cli.is_interactive", lambda: False)
    with pytest.raises(click.ClickException, match="not available inside the sandbox"):
        ensure_cwd_project({})


def test_ensure_cwd_yes_injects_project(
    tmp_path: Path,
    runtime_dir: Path,
    tmp_config: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("buddelkiste.cli.is_interactive", lambda: True)
    monkeypatch.setattr("buddelkiste.prompts.prompt_cwd_access", lambda: "yes")
    monkeypatch.setattr(
        "buddelkiste.prompts.prompt_project_features",
        lambda config: {"python": True},
    )

    result = ensure_cwd_project({})
    root = str(tmp_path.resolve())
    assert result["projects"] == [{"path": root, "features": {"python": True}}]
    assert not tmp_config.exists() or tmp_config.read_text(encoding="utf-8") == ""

    binds = get_binds(result, cwd=tmp_path)
    assert any(
        isinstance(bind, RWBindConfig) and Path(bind.source).resolve() == tmp_path.resolve()
        for bind in binds
    )


def test_ensure_cwd_always_persists_project(
    tmp_path: Path,
    runtime_dir: Path,
    tmp_config: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("buddelkiste.cli.is_interactive", lambda: True)
    monkeypatch.setattr("buddelkiste.prompts.prompt_cwd_access", lambda: "always")
    monkeypatch.setattr(
        "buddelkiste.prompts.prompt_project_features",
        lambda config: {"rust": True},
    )

    result = ensure_cwd_project({})
    root = str(tmp_path.resolve())
    assert result["projects"] == [{"path": root, "features": {"rust": True}}]
    data = tomllib.loads(tmp_config.read_text(encoding="utf-8"))
    assert "binds" not in data
    assert data["projects"] == [{"path": root, "features": {"rust": True}}]


def test_ensure_cwd_abort(
    tmp_path: Path,
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("buddelkiste.cli.is_interactive", lambda: True)
    monkeypatch.setattr("buddelkiste.prompts.prompt_cwd_access", lambda: "no")
    with pytest.raises(click.Abort):
        ensure_cwd_project({})


def test_add_bind_to_config_escapes_special_chars(
    tmp_config: Path, tmp_path: Path
) -> None:
    source = tmp_path / 'proj"quote\\slash'
    source.mkdir()
    add_bind_to_config(source, mode="ro")
    data = tomllib.loads(tmp_config.read_text(encoding="utf-8"))
    assert data["binds"][0]["source"] == str(source)


def test_get_binds_only_mounts_active_project(
    tmp_path: Path,
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = tmp_path / "active"
    other = tmp_path / "other"
    active.mkdir()
    other.mkdir()
    monkeypatch.chdir(active)
    config = {
        "projects": [
            {"path": str(active)},
            {"path": str(other)},
        ]
    }
    binds = get_binds(config, {name: False for name in FEATURE_NAMES}, cwd=active)
    sources = [
        Path(bind.source).resolve()
        for bind in binds
        if hasattr(bind, "source")
    ]
    assert active.resolve() in sources
    assert other.resolve() not in sources


def test_add_project_to_config_writes_table(tmp_config: Path, tmp_path: Path) -> None:
    source = tmp_path / "proj"
    source.mkdir()
    add_project_to_config(source, features={"python": True, "rust": True})
    data = tomllib.loads(tmp_config.read_text(encoding="utf-8"))
    key = str(source.resolve())
    assert data["projects"] == [
        {"path": key, "features": {"python": True, "rust": True}}
    ]


def test_permanent_bind_roundtrip(
    tmp_config: Path,
    tmp_path: Path,
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    source = tmp_path / "proj"
    source.mkdir()
    add_bind_to_config(source, mode="rw")

    config = load_config()
    binds = get_binds(config, {name: False for name in FEATURE_NAMES})
    assert any(
        isinstance(bind, RWBindConfig) and Path(bind.source) == source for bind in binds
    )
