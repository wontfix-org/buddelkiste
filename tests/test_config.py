from __future__ import annotations

import tomllib
from pathlib import Path

import click
import pytest

from buddelkiste.cli import (
    RWBindConfig,
    add_bind_to_config,
    add_project_to_config,
    effective_config,
    ensure_cwd_project,
    format_active_info,
    format_effective_config,
    format_toml_document,
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


def test_effective_config_applies_layers(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config = {
        "features": ["user", "git"],
        "network": {"mode": "filter", "allow": ["1.1.1.1/32"]},
        "dbus_proxy": {"talk": ["org.foo.Bar"]},
        "executables": {
            "python": {
                "features": {"python": True},
                "network": {"mode": "none"},
            }
        },
        "projects": [{"path": str(repo), "features": {"rust": True}}],
        "binds": [{"source": "/tmp", "mode": "ro"}],
        "bind_conflicts": "weaker",
    }
    merged = effective_config(config, executable="python", cwd=repo)
    assert merged["bind_conflicts"] == "weaker"
    assert merged["bind_symlinks"] == "follow"
    assert merged["features"]["user"] is True
    assert merged["features"]["git"] is True
    assert merged["features"]["python"] is True
    assert merged["features"]["rust"] is True
    assert merged["features"]["ssh"] is False
    assert merged["network"]["mode"] == "none"
    assert merged["network"]["backend"] == "pasta"
    assert merged["dbus_proxy"]["talk"] == ["org.foo.Bar"]
    assert merged["binds"] == [{"source": "/tmp", "mode": "ro"}]
    assert "executables" not in merged
    assert "projects" not in merged


def test_format_active_info_lists_enabled_settings(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config = {
        "features": ["user", "git"],
        "network": {"mode": "filter", "allow": ["1.1.1.1/32"]},
        "dbus_proxy": {"talk": ["org.foo.Bar"]},
        "executables": {
            "python": {
                "features": {"python": True},
                "args": ["-u"],
                "network": {"mode": "none"},
            }
        },
        "projects": [{"path": str(repo), "features": {"rust": True}}],
        "binds": [
            {"source": "/tmp", "mode": "ro"},
            {"git": "/some/repo", "mode": "ro"},
        ],
        "envvars": [{"name": "FOO", "value": "bar"}, {"name": "FROM_ENV"}],
        "docker_proxy": {"images": ["alpine:3.20"]},
        "feature": {"zig": {"description": "Zig toolchain cache"}},
    }
    text = format_active_info(config, executable="python", cwd=repo)
    assert f"project: {repo.resolve()}" in text
    assert "consider_projects: true" in text
    assert "executable: python" in text
    assert "args (1):\n  - -u\n" in text
    assert "bind_conflicts: error" in text
    assert "bind_symlinks: follow" in text
    assert "  - user\n" in text
    assert "  - git\n" in text
    assert "  - python\n" in text
    assert "  - rust\n" in text
    assert "  mode: none" in text
    assert "  - org.foo.Bar\n" in text
    assert "  - /tmp (ro)\n" in text
    assert "  - /some/repo (ro)\n" in text
    assert "  - FOO=bar\n" in text
    assert "  - FROM_ENV (from environment)\n" in text
    assert "docker_proxy:" in text
    assert "  - alpine:3.20\n" in text
    assert "Zig toolchain cache" not in text


def test_format_active_info_lists_resolved_binds_and_notes(
    tmp_path: Path, runtime_dir: Path
) -> None:
    parent = tmp_path / "local"
    parent.mkdir()
    real = parent / "gtk-dark.css"
    real.write_text("x", encoding="utf-8")
    link = parent / "gtk.css"
    link.symlink_to(real)
    config = {
        "features": [],
        "binds": [
            {"source": str(parent), "mode": "ro"},
            {"source": str(link), "mode": "ro"},
        ],
    }
    text = format_active_info(config, cwd=tmp_path)
    assert "resolved binds" in text
    assert f"  - {parent} (ro)\n" in text
    assert "bind_symlinks notes" in text
    assert "bind_symlinks follow" in text
    assert str(link) in text
    assert str(real.resolve()) in text
    assert "skip" in text
    assert str(parent) in text


def test_format_toml_document_roundtrip() -> None:
    text = format_toml_document(
        {
            "shims": True,
            "features": {"user": True, "dbus-proxy": False},
            "quoted key": "value",
            "binds": [{"source": "/tmp", "mode": "ro"}],
        },
        comments=["cwd: /tmp"],
    )
    assert text.startswith("# cwd: /tmp\n")
    data = tomllib.loads(text)
    assert data["shims"] is True
    assert data["features"]["user"] is True
    assert data["features"]["dbus-proxy"] is False
    assert data["quoted key"] == "value"
    assert data["binds"] == [{"source": "/tmp", "mode": "ro"}]


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


def test_ensure_cwd_covered_by_project_subdir_is_noop(
    tmp_path: Path,
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = tmp_path / "src"
    child.mkdir()
    monkeypatch.chdir(child)
    config = {"projects": [{"path": str(tmp_path)}]}
    result = ensure_cwd_project(config)
    assert result == config


def test_ensure_cwd_bind_does_not_cover(
    tmp_path: Path,
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("buddelkiste.cli.is_interactive", lambda: False)
    config = {"binds": [{"source": str(tmp_path), "mode": "rw"}]}
    with pytest.raises(click.ClickException, match="not under a configured project"):
        ensure_cwd_project(config)


def test_ensure_cwd_noninteractive_errors(
    tmp_path: Path,
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("buddelkiste.cli.is_interactive", lambda: False)
    with pytest.raises(click.ClickException, match="not under a configured project"):
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
        lambda config, **kwargs: {"python": True},
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
        lambda config, **kwargs: {"rust": True},
    )

    result = ensure_cwd_project({})
    root = str(tmp_path.resolve())
    assert result["projects"] == [{"path": root, "features": {"rust": True}}]
    data = tomllib.loads(tmp_config.read_text(encoding="utf-8"))
    assert "binds" not in data
    assert data["projects"] == [{"path": root, "features": {"rust": True}}]


def test_ensure_cwd_forwards_executable_to_feature_prompt(
    tmp_path: Path,
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("buddelkiste.cli.is_interactive", lambda: True)
    monkeypatch.setattr("buddelkiste.prompts.prompt_cwd_access", lambda: "yes")
    seen: dict = {}

    def fake_features(config, **kwargs):
        seen.update(kwargs)
        return {}

    monkeypatch.setattr("buddelkiste.prompts.prompt_project_features", fake_features)
    ensure_cwd_project(
        {},
        executable="/usr/bin/python",
        enable=("ssh",),
        disable=("rust",),
    )
    assert seen["executable"] == "/usr/bin/python"
    assert seen["enable"] == ("ssh",)
    assert seen["disable"] == ("rust",)


def test_ensure_cwd_consider_projects_false_skips_uncovered(
    tmp_path: Path,
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("buddelkiste.cli.is_interactive", lambda: False)

    def fail_prompt(*_args, **_kwargs):
        raise AssertionError("prompted")

    monkeypatch.setattr("buddelkiste.prompts.prompt_cwd_access", fail_prompt)
    config = {"executables": {"cursor-agent": {"consider_projects": False}}}
    result = ensure_cwd_project(config, executable="/usr/bin/cursor-agent")
    assert result is config
    assert "projects" not in result


def test_ensure_cwd_consider_projects_false_inside_project(
    tmp_path: Path,
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.chdir(repo)
    monkeypatch.setattr("buddelkiste.cli.is_interactive", lambda: True)

    def fail_prompt(*_args, **_kwargs):
        raise AssertionError("prompted")

    monkeypatch.setattr("buddelkiste.prompts.prompt_cwd_access", fail_prompt)
    config = {
        "executables": {"cursor": {"consider_projects": False}},
        "projects": [{"path": str(repo), "features": {"python": True}}],
    }
    result = ensure_cwd_project(config, executable="cursor")
    assert result is config
    assert result["projects"] == config["projects"]


def test_ensure_cwd_consider_projects_true_still_requires_project(
    tmp_path: Path,
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("buddelkiste.cli.is_interactive", lambda: False)
    config = {"executables": {"python": {"consider_projects": True}}}
    with pytest.raises(click.ClickException, match="not under a configured project"):
        ensure_cwd_project(config, executable="python")


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


def test_get_binds_skips_project_when_not_considered(
    tmp_path: Path,
    runtime_dir: Path,
) -> None:
    active = tmp_path / "active"
    active.mkdir()
    enabled = {name: False for name in FEATURE_NAMES}
    skipped = get_binds(
        {
            "executables": {"cursor-agent": {"consider_projects": False}},
            "projects": [{"path": str(active)}],
        },
        enabled,
        executable="cursor-agent",
        cwd=active,
    )
    skipped_sources = [
        Path(bind.source).resolve() for bind in skipped if hasattr(bind, "source")
    ]
    assert active.resolve() not in skipped_sources

    kept = get_binds(
        {
            "executables": {"cursor-agent": {"consider_projects": True}},
            "projects": [{"path": str(active)}],
        },
        enabled,
        executable="cursor-agent",
        cwd=active,
    )
    kept_sources = [
        Path(bind.source).resolve() for bind in kept if hasattr(bind, "source")
    ]
    assert active.resolve() in kept_sources


def test_format_active_info_notes_ignored_project(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config = {
        "executables": {
            "cursor-agent": {
                "consider_projects": False,
                "features": ["cursor"],
            }
        },
        "projects": [{"path": str(repo), "features": {"rust": True}}],
    }
    text = format_active_info(config, executable="cursor-agent", cwd=repo)
    assert f"project: {repo.resolve()} (not applied)" in text
    assert "consider_projects: false" in text
    assert "  - cursor\n" in text
    assert "  - rust\n" not in text
    shown = format_effective_config(config, executable="cursor-agent", cwd=repo)
    assert f"# project: {repo.resolve()} (not applied)" in shown
    assert "# consider_projects: false" in shown


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
