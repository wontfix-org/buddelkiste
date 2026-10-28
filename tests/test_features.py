from __future__ import annotations

import socket
from pathlib import Path
from unittest.mock import MagicMock

import click
import pytest

from buddelkiste.features import (
    FEATURE_NAMES,
    FEATURES,
    Feature,
    base_binds,
    binds_from_spec,
    check_feature_requirements,
    clear_feature_caches,
    cursor_binds,
    dbus_binds,
    dbus_proxy_setup,
    executable_considers_projects,
    expand_bind_path,
    feature_binds,
    feature_env_var_names,
    format_features_help,
    interpolate_env,
    load_entry_point_features,
    load_feature_registry,
    lookup_project_config,
    lookup_project_configs,
    project_discovery,
    python_binds,
    resolve_features,
    resolved_project_root,
    rust_binds,
    user_binds,
    xdg_open_binds,
)
from tests.conftest import init_git_index, needs_git


def test_feature_catalog_is_topic_oriented() -> None:
    assert "cursor" in FEATURES
    assert "python" in FEATURES
    assert "rust" in FEATURES
    assert "ssh" in FEATURES
    assert "docker" in FEATURES
    assert "docker-proxy" in FEATURES
    assert "docker-instance" in FEATURES
    assert "dbus" in FEATURES
    assert "dbus-proxy" in FEATURES
    assert "xdg-open" in FEATURES
    assert "user" in FEATURES
    assert "home" not in FEATURES
    assert "locale" not in FEATURES
    assert "term" not in FEATURES
    # Type-oriented names should not be features.
    assert "gpu" not in FEATURES
    assert "audio" not in FEATURES
    assert "display" not in FEATURES
    assert "devtools" not in FEATURES


def test_resolve_features_defaults_only_user() -> None:
    enabled = resolve_features({})
    registry = load_feature_registry({})
    for name, feature in registry.items():
        assert enabled[name] is feature.default
    assert enabled["user"] is True
    assert enabled["docker-proxy"] is False
    assert enabled["docker-instance"] is False
    assert enabled["docker"] is False
    assert enabled["cursor"] is False


def test_resolve_features_config_table_and_cli_precedence() -> None:
    enabled = resolve_features(
        {"features": {"gui": False, "python": False}},
        enable=["python"],
        disable=["ssh"],
    )
    assert enabled["gui"] is False
    assert enabled["python"] is True  # CLI enable wins over config
    assert enabled["ssh"] is False
    assert enabled["user"] is True  # still the only default-on feature
    assert enabled["cursor"] is False


def test_resolve_features_global_list_is_allowlist() -> None:
    enabled = resolve_features({"features": ["git", "ssh"]})
    assert enabled["git"] is True
    assert enabled["ssh"] is True
    assert enabled["python"] is False
    assert enabled["cursor"] is False


def test_resolve_features_per_executable_list() -> None:
    config = {
        "features": ["git"],
        "executables": {
            "cursor-agent": {"features": ["cursor", "ssh"]},
            "/usr/bin/python": {"features": ["python", "git"]},
        },
    }
    by_basename = resolve_features(config, executable="/opt/bin/cursor-agent")
    assert by_basename["cursor"] is True
    assert by_basename["ssh"] is True
    assert by_basename["git"] is False

    # Path keys match by file name, including a different directory or a bare name.
    for executable in ("/usr/bin/python", "/opt/python", "python"):
        by_name = resolve_features(config, executable=executable)
        assert by_name["python"] is True
        assert by_name["git"] is True
        assert by_name["cursor"] is False

    other = resolve_features(config, executable="/usr/bin/python3")
    assert other["python"] is False
    assert other["git"] is True

    # No executable → global only (shell fallback).
    global_only = resolve_features(config, executable=None)
    assert global_only["git"] is True
    assert global_only["cursor"] is False


def test_resolve_features_file_name_first_key_wins() -> None:
    enabled = resolve_features(
        {
            "executables": {
                "python": {"features": ["git"]},
                "/usr/bin/python": {"features": ["python"]},
            }
        },
        executable="/usr/bin/python",
    )
    assert enabled["git"] is True
    assert enabled["python"] is False


def test_resolve_features_per_executable_table_overrides_global() -> None:
    enabled = resolve_features(
        {
            "features": ["git", "ssh", "python"],
            "executables": {
                "python": {"features": {"docker": True, "ssh": False}},
            },
        },
        executable="python",
    )
    assert enabled["git"] is True
    assert enabled["python"] is True
    assert enabled["docker"] is True
    assert enabled["ssh"] is False


def test_resolve_features_project_table_adds_on_executable_list(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config = {
        "executables": {"cursor-agent": {"features": ["cursor", "git"]}},
        "projects": [
            {"path": str(repo), "features": {"python": True, "rust": True}}
        ],
    }
    enabled = resolve_features(config, executable="cursor-agent", cwd=repo)
    assert enabled["cursor"] is True
    assert enabled["git"] is True
    assert enabled["python"] is True
    assert enabled["rust"] is True


def test_resolve_features_skips_project_when_not_considered(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config = {
        "executables": {
            "cursor-agent": {
                "consider_projects": False,
                "features": ["cursor", "git"],
            }
        },
        "projects": [
            {"path": str(repo), "features": {"python": True, "rust": True}}
        ],
    }
    enabled = resolve_features(
        config, executable="cursor-agent", enable=("ssh",), cwd=repo
    )
    assert enabled["cursor"] is True
    assert enabled["git"] is True
    assert enabled["ssh"] is True
    assert enabled["python"] is False
    assert enabled["rust"] is False


def test_resolve_features_explicit_consider_projects_applies_project(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config = {
        "executables": {
            "cursor-agent": {
                "consider_projects": True,
                "features": ["cursor", "git"],
            }
        },
        "projects": [
            {"path": str(repo), "features": {"python": True, "rust": True}}
        ],
    }
    enabled = resolve_features(config, executable="cursor-agent", cwd=repo)
    assert enabled["python"] is True
    assert enabled["rust"] is True


def test_executable_considers_projects_defaults_true() -> None:
    assert executable_considers_projects({}, None) is True
    assert executable_considers_projects({}, "python") is True
    assert (
        executable_considers_projects({"executables": {"python": {}}}, "python")
        is True
    )
    assert (
        executable_considers_projects(
            {"executables": {"python": {"consider_projects": True}}},
            "/usr/bin/python",
        )
        is True
    )


def test_executable_considers_projects_false() -> None:
    assert (
        executable_considers_projects(
            {"executables": {"cursor-agent": {"consider_projects": False}}},
            "cursor-agent",
        )
        is False
    )


def test_executable_considers_projects_rejects_non_bool() -> None:
    with pytest.raises(click.ClickException, match="consider_projects"):
        executable_considers_projects(
            {"executables": {"cursor": {"consider_projects": "no"}}},
            "cursor",
        )


def test_resolve_features_project_list_is_allowlist(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config = {
        "executables": {"cursor-agent": {"features": ["cursor", "git"]}},
        "projects": [{"path": str(repo), "features": ["python"]}],
    }
    enabled = resolve_features(config, executable="cursor-agent", cwd=repo)
    assert enabled["python"] is True
    assert enabled["cursor"] is False
    assert enabled["git"] is False


def test_lookup_project_most_specific_wins(tmp_path: Path) -> None:
    parent = tmp_path / "src"
    child = parent / "app"
    child.mkdir(parents=True)
    config = {
        "projects": [
            {"path": str(parent), "features": {"git": True}},
            {"path": str(child), "features": {"python": True}},
        ]
    }
    found = lookup_project_config(config, cwd=child)
    assert found is not None
    root, table = found
    assert root == child.resolve()
    assert table["features"] == {"python": True}

    enabled = resolve_features(config, cwd=child)
    assert enabled["python"] is True
    assert enabled["git"] is False

    explicit = {**config, "project_discovery": "discover"}
    assert lookup_project_configs(explicit, cwd=child) == [found]
    assert project_discovery({}) == "discover"


def test_project_discovery_cwd_requires_exact_path(tmp_path: Path) -> None:
    parent = tmp_path / "src"
    child = parent / "app"
    nested = child / "pkg"
    nested.mkdir(parents=True)
    config = {
        "project_discovery": "cwd",
        "projects": [
            {"path": str(parent), "features": {"git": True}},
            {"path": str(child), "features": {"python": True}},
        ],
    }
    found = lookup_project_config(config, cwd=child)
    assert found is not None
    assert found[0] == child.resolve()
    assert lookup_project_configs(config, cwd=nested) == []
    assert lookup_project_config(config, cwd=parent)[0] == parent.resolve()

    enabled = resolve_features(config, cwd=nested)
    assert enabled["git"] is False
    assert enabled["python"] is False
    assert resolved_project_root(config, cwd=nested) == nested.resolve()


def test_project_discovery_all_merges_outer_to_inner(tmp_path: Path) -> None:
    parent = tmp_path / "src"
    child = parent / "app"
    child.mkdir(parents=True)
    config = {
        "project_discovery": "discover-all",
        "projects": [
            {"path": str(child), "features": {"python": True}},
            {"path": str(parent), "features": {"git": True}},
        ],
    }
    found = lookup_project_configs(config, cwd=child)
    assert [root for root, _table in found] == [parent.resolve(), child.resolve()]
    assert lookup_project_config(config, cwd=child) == found[-1]
    assert resolved_project_root(config, cwd=child) == child.resolve()

    enabled = resolve_features(config, cwd=child)
    assert enabled["git"] is True
    assert enabled["python"] is True


def test_project_discovery_all_child_list_replaces(tmp_path: Path) -> None:
    parent = tmp_path / "src"
    child = parent / "app"
    child.mkdir(parents=True)
    config = {
        "project_discovery": "discover-all",
        "projects": [
            {"path": str(parent), "features": {"git": True, "python": True}},
            {"path": str(child), "features": ["rust"]},
        ],
    }
    enabled = resolve_features(config, cwd=child)
    assert enabled["rust"] is True
    assert enabled["git"] is False
    assert enabled["python"] is False


def test_project_discovery_all_duplicate_path_keeps_later(tmp_path: Path) -> None:
    parent = tmp_path / "src"
    child = parent / "app"
    child.mkdir(parents=True)
    config = {
        "project_discovery": "discover-all",
        "projects": [
            {"path": str(parent), "features": {"git": True}},
            {"path": str(parent), "features": {"ssh": True}},
            {"path": str(child), "features": {"python": True}},
        ],
    }
    found = lookup_project_configs(config, cwd=child)
    assert found[0][1]["features"] == {"ssh": True}
    enabled = resolve_features(config, cwd=child)
    assert enabled["ssh"] is True
    assert enabled["python"] is True
    assert enabled["git"] is False


def test_project_discovery_rejects_unknown(tmp_path: Path) -> None:
    with pytest.raises(click.ClickException, match="project_discovery"):
        project_discovery({"project_discovery": "nope"})
    with pytest.raises(click.ClickException, match="project_discovery"):
        lookup_project_config({"project_discovery": 1}, cwd=tmp_path)


def test_lookup_project_later_same_path_wins(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config = {
        "projects": [
            {"path": str(repo), "features": {"git": True}},
            {"path": str(repo), "features": {"python": True}},
        ]
    }
    found = lookup_project_config(config, cwd=repo)
    assert found is not None
    assert found[1]["features"] == {"python": True}
    assert resolved_project_root({}, cwd=repo) == repo.resolve()
    assert resolved_project_root(config, cwd=repo) == repo.resolve()


def test_resolve_features_unknown_raises() -> None:
    with pytest.raises(click.ClickException, match="Unknown feature in config"):
        resolve_features({"features": {"nope": True}})
    with pytest.raises(click.ClickException, match="Unknown feature in config"):
        resolve_features({"features": ["nope"]})
    with pytest.raises(click.ClickException, match="Unknown feature: nope"):
        resolve_features({}, enable=["nope"])
    with pytest.raises(click.ClickException, match="Unknown feature: nope"):
        resolve_features({}, disable=["nope"])
    with pytest.raises(click.ClickException, match="for executable"):
        resolve_features(
            {"executables": {"foo": {"features": ["nope"]}}},
            executable="foo",
        )


def test_interpolate_env_supports_braced_and_bare(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CARGO_HOME", "/tmp/cargo")
    monkeypatch.setenv("HOME", "/home/me")
    assert interpolate_env("$CARGO_HOME/git") == "/tmp/cargo/git"
    assert interpolate_env("${HOME}/.rustup") == "/home/me/.rustup"
    with pytest.raises(click.ClickException, match="NOT_SET"):
        interpolate_env("$NOT_SET")


def test_expand_bind_path_expands_tilde(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    assert expand_bind_path("~/tools") == str(home / "tools")
    assert expand_bind_path("${HOME}/tools") == str(home / "tools")


def test_toml_custom_feature_registry_and_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    zig = tmp_path / "zig"
    zig.mkdir()
    monkeypatch.setenv("ZIG_GLOBAL_CACHE_DIR", str(zig))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()

    config = {
        "features": ["zig"],
        "feature": {
            "zig": {
                "description": "Zig toolchain cache",
                "default": False,
                "env": ["ZIG_GLOBAL_CACHE_DIR"],
                "binds": [
                    {"source": "$ZIG_GLOBAL_CACHE_DIR", "mode": "rw"},
                    {"source": "${HOME}/.zig", "mode": "ro"},
                ],
            }
        },
    }
    registry = load_feature_registry(config)
    assert "zig" in registry
    assert registry["zig"].env_vars == ("ZIG_GLOBAL_CACHE_DIR",)
    assert "config:[feature.zig]" in format_features_help(config)

    enabled = resolve_features(config)
    assert enabled["zig"] is True
    assert enabled["git"] is False

    binds = feature_binds(enabled, config)
    sources = {getattr(b, "source", None) for b in binds}
    assert str(zig) in sources
    assert str(tmp_path / "home" / ".zig") in sources

    env_names = feature_env_var_names(enabled, config)
    assert "ZIG_GLOBAL_CACHE_DIR" in env_names
    assert "VIRTUAL_ENV" not in env_names


def test_toml_feature_rejects_builtin_name() -> None:
    with pytest.raises(click.ClickException, match="conflicts with existing"):
        load_feature_registry({"feature": {"python": {"env": ["FOO"]}}})


def test_toml_feature_rejects_unknown_keys() -> None:
    with pytest.raises(click.ClickException, match="unknown keys"):
        load_feature_registry({"feature": {"mine": {"script": "nope"}}})


def test_binds_from_spec_glob_matches_files_and_dirs(tmp_path: Path) -> None:
    file_a = tmp_path / "a.txt"
    file_b = tmp_path / "b.txt"
    nested = tmp_path / "dir"
    file_a.write_text("a", encoding="utf-8")
    file_b.write_text("b", encoding="utf-8")
    nested.mkdir()

    binds = binds_from_spec({"glob": str(tmp_path / "*"), "mode": "rw"}, where="binds[0]")
    sources = {bind.source for bind in binds}
    assert sources == {str(file_a), str(file_b), str(nested)}
    assert all(bind.source == bind.target for bind in binds)


def test_binds_from_spec_glob_expands_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BIND_ROOT", str(tmp_path))
    path = tmp_path / "keep"
    path.write_text("x", encoding="utf-8")
    binds = binds_from_spec({"glob": "$BIND_ROOT/k*"}, where="binds[0]")
    assert [bind.source for bind in binds] == [str(path)]


def test_binds_from_spec_nullglob_empty(tmp_path: Path) -> None:
    assert (
        binds_from_spec(
            {"glob": str(tmp_path / "missing*"), "nullglob": True},
            where="binds[0]",
        )
        == []
    )


def test_binds_from_spec_empty_glob_errors(tmp_path: Path) -> None:
    with pytest.raises(click.ClickException, match="matched nothing"):
        binds_from_spec({"glob": str(tmp_path / "missing*")}, where="binds[0]")


def test_binds_from_spec_rejects_source_and_glob(tmp_path: Path) -> None:
    path = tmp_path / "x"
    path.write_text("x", encoding="utf-8")
    with pytest.raises(click.ClickException, match="both 'source' and 'glob'"):
        binds_from_spec({"source": str(path), "glob": str(tmp_path / "*")})


def test_binds_from_spec_rejects_nullglob_without_glob() -> None:
    with pytest.raises(click.ClickException, match="nullglob"):
        binds_from_spec({"source": "/tmp", "nullglob": True})


def test_binds_from_spec_rejects_non_bool_nullglob(tmp_path: Path) -> None:
    with pytest.raises(click.ClickException, match="must be a boolean"):
        binds_from_spec({"glob": str(tmp_path / "*"), "nullglob": "true"})


def test_binds_from_spec_requires_source_or_glob() -> None:
    with pytest.raises(click.ClickException, match="'source', 'glob', or 'git'"):
        binds_from_spec({"mode": "ro"})


def test_binds_from_spec_rejects_bad_symlink(tmp_path: Path) -> None:
    path = tmp_path / "x"
    path.write_text("x", encoding="utf-8")
    with pytest.raises(click.ClickException, match="symlink"):
        binds_from_spec({"source": str(path), "symlink": "copy"})


def test_binds_from_spec_sets_symlink_override(tmp_path: Path) -> None:
    path = tmp_path / "x"
    path.write_text("x", encoding="utf-8")
    binds = binds_from_spec(
        {"source": str(path), "mode": "ro", "symlink": "preserve"},
        where="binds[0]",
    )
    assert binds[0].symlink == "preserve"


def test_toml_feature_glob_binds(tmp_path: Path) -> None:
    one = tmp_path / "one.cfg"
    two = tmp_path / "two.cfg"
    one.write_text("1", encoding="utf-8")
    two.write_text("2", encoding="utf-8")
    config = {
        "feature": {
            "cfgs": {
                "binds": [{"glob": str(tmp_path / "*.cfg"), "mode": "ro"}],
            }
        }
    }
    registry = load_feature_registry(config)
    sources = {bind.source for bind in registry["cfgs"].binds()}
    assert sources == {str(one), str(two)}


@needs_git
def test_binds_from_spec_git_matches_tracked_files_only(tmp_path: Path) -> None:
    repo = init_git_index(
        tmp_path / "repo",
        {"a.txt": "a", "src/nested.txt": "n"},
    )
    (repo / "untracked.txt").write_text("nope", encoding="utf-8")

    binds = binds_from_spec({"git": str(repo), "mode": "rw"}, where="binds[0]")
    sources = {bind.source for bind in binds}
    assert sources == {str(repo / "a.txt"), str(repo / "src" / "nested.txt")}
    assert all(bind.source == bind.target for bind in binds)


@needs_git
def test_binds_from_spec_git_includes_file_symlink(tmp_path: Path) -> None:
    import os
    import subprocess

    repo = init_git_index(tmp_path / "repo", {"real.txt": "x"})
    link = repo / "link.txt"
    link.symlink_to("real.txt")
    env = os.environ.copy()
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        env.pop(name, None)
    subprocess.run(
        ["git", "add", "--", "link.txt"],
        cwd=repo,
        check=True,
        capture_output=True,
        env=env,
    )
    binds = binds_from_spec({"git": str(repo), "mode": "ro"}, where="binds[0]")
    sources = {bind.source for bind in binds}
    assert str(link) in sources
    assert str(repo / "real.txt") in sources


@needs_git
def test_binds_from_spec_git_target_uses_relpath(tmp_path: Path) -> None:
    repo = init_git_index(tmp_path / "repo", {"src/nested.txt": "n"})
    binds = binds_from_spec(
        {"git": str(repo), "target": "/mnt/extra", "mode": "ro"},
        where="binds[0]",
    )
    assert len(binds) == 1
    assert binds[0].source == str(repo / "src" / "nested.txt")
    assert binds[0].target == "/mnt/extra/src/nested.txt"


@needs_git
def test_binds_from_spec_git_expands_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = init_git_index(tmp_path / "repo", {"keep.txt": "x"})
    monkeypatch.setenv("BIND_ROOT", str(repo))
    binds = binds_from_spec({"git": "$BIND_ROOT"}, where="binds[0]")
    assert [bind.source for bind in binds] == [str(repo / "keep.txt")]


@needs_git
def test_binds_from_spec_git_nullglob_empty(tmp_path: Path) -> None:
    repo = init_git_index(tmp_path / "empty")
    assert (
        binds_from_spec(
            {"git": str(repo), "nullglob": True},
            where="binds[0]",
        )
        == []
    )


@needs_git
def test_binds_from_spec_empty_git_errors(tmp_path: Path) -> None:
    repo = init_git_index(tmp_path / "empty")
    with pytest.raises(click.ClickException, match="matched nothing"):
        binds_from_spec({"git": str(repo)}, where="binds[0]")


@needs_git
def test_binds_from_spec_git_not_a_repository(tmp_path: Path) -> None:
    with pytest.raises(click.ClickException, match="not a git repository"):
        binds_from_spec({"git": str(tmp_path / "missing")}, where="binds[0]")


@needs_git
def test_binds_from_spec_rejects_source_and_git(tmp_path: Path) -> None:
    repo = init_git_index(tmp_path / "repo", {"a.txt": "a"})
    with pytest.raises(click.ClickException, match="both 'source' and 'git'"):
        binds_from_spec({"source": str(repo / "a.txt"), "git": str(repo)})


@needs_git
def test_binds_from_spec_rejects_glob_and_git(tmp_path: Path) -> None:
    repo = init_git_index(tmp_path / "repo", {"a.txt": "a"})
    with pytest.raises(click.ClickException, match="both 'glob' and 'git'"):
        binds_from_spec({"glob": str(repo / "*"), "git": str(repo)})


@needs_git
def test_binds_from_spec_git_ignores_git_dir_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = init_git_index(tmp_path / "repo", {"keep.txt": "x"})
    other = init_git_index(tmp_path / "other", {"other.txt": "y"})
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    binds = binds_from_spec({"git": str(repo)}, where="binds[0]")
    assert [bind.source for bind in binds] == [str(repo / "keep.txt")]


@needs_git
def test_toml_feature_git_binds(tmp_path: Path) -> None:
    repo = init_git_index(tmp_path / "repo", {"one.cfg": "1", "two.cfg": "2"})
    (repo / "skip.cfg").write_text("3", encoding="utf-8")
    config = {
        "feature": {
            "cfgs": {
                "binds": [{"git": str(repo), "mode": "ro"}],
            }
        }
    }
    registry = load_feature_registry(config)
    sources = {bind.source for bind in registry["cfgs"].binds()}
    assert sources == {str(repo / "one.cfg"), str(repo / "two.cfg")}


def test_toml_bind_rejects_read_only_key() -> None:
    config = {
        "feature": {
            "mine": {
                "binds": [{"source": "/tmp", "read_only": True}],
            }
        }
    }
    registry = load_feature_registry(config)
    with pytest.raises(click.ClickException, match="read_only"):
        registry["mine"].binds()


def test_toml_bind_overlay_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from buddelkiste.binds import (
        OverlayBindConfig,
        TmpOverlayBindConfig,
        overlay_cache_upper,
    )

    lower = tmp_path / "lower"
    lower.mkdir()
    monkeypatch.setenv("UPPER", str(tmp_path / "upper"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    config = {
        "feature": {
            "ov": {
                "binds": [
                    {"source": str(lower), "mode": "tmp-overlay"},
                    {"source": str(lower), "mode": "overlay:$UPPER"},
                    {"source": str(lower), "mode": "overlay"},
                ],
            }
        }
    }
    registry = load_feature_registry(config)
    binds = registry["ov"].binds()
    assert isinstance(binds[0], TmpOverlayBindConfig)
    assert isinstance(binds[1], OverlayBindConfig)
    assert binds[1].upper == str(tmp_path / "upper")
    assert isinstance(binds[2], OverlayBindConfig)
    assert Path(binds[2].upper) == overlay_cache_upper(lower)


def test_enable_custom_toml_feature_via_cli_flag() -> None:
    config = {
        "feature": {
            "labs": {
                "default": False,
                "env": ["LAB_TOKEN"],
                "binds": [{"source": "${HOME}/labs", "mode": "ro"}],
            }
        }
    }
    enabled = resolve_features(config, enable=["labs"])
    assert enabled["labs"] is True
    assert "LAB_TOKEN" in feature_env_var_names(enabled, config)


def test_feature_binds_include_only_enabled_topics(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    (home / ".pip").mkdir()
    (home / ".cursor").mkdir()

    enabled = {name: False for name in FEATURE_NAMES}
    enabled["python"] = True

    binds = feature_binds(enabled)
    sources = {getattr(b, "source", None) for b in binds}
    assert str(home / ".pip") in sources
    assert str(home / ".cursor") not in sources
    assert str(home / ".cache") not in sources
    assert "/usr" in sources  # base
    assert any(
        getattr(bind, "source", None) == "/usr"
        and getattr(bind, "origin", None) == "base"
        for bind in binds
    )
    assert any(
        getattr(bind, "source", None) == str(home / ".pip")
        and getattr(bind, "origin", None) == "feature python"
        for bind in binds
    )


def test_base_binds_always_present(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    sources = {getattr(b, "source", None) for b in base_binds()}
    assert "/usr" in sources
    assert str(tmp_path / "home" / ".local") not in sources
    assert str(tmp_path / "home" / ".cache") not in sources
    assert "/usr/libexec/flatpak-xdg-utils/xdg-open" not in sources
    assert "/run/dbus/system_bus_socket" not in sources
    assert str(runtime_dir / "bus") not in sources


def test_topic_bind_helpers(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    assert any(getattr(b, "source", None) == "/opt/cursor-agent" for b in cursor_binds())
    assert any(str(home / ".pip") == getattr(b, "source", None) for b in python_binds())
    rust_sources = {getattr(b, "source", None) for b in rust_binds()}
    assert str(home / ".cargo") in rust_sources
    assert str(home / ".rustup") in rust_sources
    dbus_sources = {getattr(b, "source", None) for b in dbus_binds()}
    assert "/run/dbus/system_bus_socket" in dbus_sources
    assert str(runtime_dir / "bus") in dbus_sources
    assert str(runtime_dir / "dbus-1") in dbus_sources
    assert any(
        getattr(b, "source", None) == "/usr/libexec/flatpak-xdg-utils/xdg-open"
        for b in xdg_open_binds()
    )
    home_sources = {getattr(b, "source", None) for b in user_binds()}
    assert str(home / ".local") in home_sources
    assert str(home / ".cache") in home_sources


def test_rust_feature_binds_and_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    cargo = tmp_path / "custom-cargo"
    rustup = tmp_path / "custom-rustup"
    cargo.mkdir()
    rustup.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CARGO_HOME", str(cargo))
    monkeypatch.setenv("RUSTUP_HOME", str(rustup))

    enabled = {name: False for name in FEATURE_NAMES}
    sources_off = {getattr(b, "source", None) for b in feature_binds(enabled)}
    assert str(cargo) not in sources_off
    assert "CARGO_HOME" not in feature_env_var_names(enabled)

    enabled["rust"] = True
    sources_on = {getattr(b, "source", None) for b in feature_binds(enabled)}
    assert str(cargo) in sources_on
    assert str(rustup) in sources_on
    names = feature_env_var_names(enabled)
    assert "CARGO_HOME" in names
    assert "RUSTUP_HOME" in names


def test_dbus_feature_binds_and_env(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()

    enabled = {name: False for name in FEATURE_NAMES}
    sources_off = {getattr(b, "source", None) for b in feature_binds(enabled)}
    assert "/run/dbus/system_bus_socket" not in sources_off
    assert "DBUS_SESSION_BUS_ADDRESS" not in feature_env_var_names(enabled)

    enabled["dbus"] = True
    sources_on = {getattr(b, "source", None) for b in feature_binds(enabled)}
    assert "/run/dbus/system_bus_socket" in sources_on
    assert str(runtime_dir / "bus") in sources_on
    assert "DBUS_SESSION_BUS_ADDRESS" in feature_env_var_names(enabled)


def test_dbus_proxy_feature_setup(
    runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (runtime_dir / "bus").touch()
    monkeypatch.setattr(
        "buddelkiste.features.which",
        lambda name: "/usr/bin/xdg-dbus-proxy" if name == "xdg-dbus-proxy" else None,
    )
    monkeypatch.setattr("buddelkiste.features.time.sleep", lambda _t: None)

    captured: dict[str, object] = {}

    def fake_popen(*args, **kwargs):
        cmd = list(args[0])
        captured["cmd"] = cmd
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(cmd[2])
        captured["listener"] = listener
        proc = MagicMock()
        proc.poll.return_value = None
        proc.wait.return_value = 0
        captured["proc"] = proc
        return proc

    monkeypatch.setattr("buddelkiste.features.subprocess.Popen", fake_popen)
    monkeypatch.setattr("buddelkiste.cli.load_config", dict)

    with dbus_proxy_setup() as setup_args:
        assert "--setenv" in setup_args
        idx = setup_args.index("--setenv")
        assert setup_args[idx : idx + 2] == ["--setenv", "DBUS_SESSION_BUS_ADDRESS"]
        assert setup_args[idx + 2].startswith("unix:path=")
        proxy_socket = setup_args[idx + 2].removeprefix("unix:path=")
        assert "--ro-bind" in setup_args
        assert proxy_socket in setup_args
        assert captured["cmd"][2] == proxy_socket
        assert "--filter" not in captured["cmd"]
        assert "--talk=*" not in captured["cmd"]
        assert "--own=*" not in captured["cmd"]

    proc = captured["proc"]
    proc.terminate.assert_called_once()
    captured["listener"].close()


def test_dbus_proxy_feature_requires_binary(
    runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (runtime_dir / "bus").touch()
    monkeypatch.setattr("buddelkiste.features.which", lambda _name: None)
    with pytest.raises(click.ClickException, match="xdg-dbus-proxy"), dbus_proxy_setup():
        pass


def test_user_and_xdg_open_features(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))

    enabled = {name: False for name in FEATURE_NAMES}
    sources_off = {getattr(b, "source", None) for b in feature_binds(enabled)}
    assert str(home / ".local") not in sources_off
    assert str(home / ".cache") not in sources_off
    assert "/usr/libexec/flatpak-xdg-utils/xdg-open" not in sources_off

    enabled["user"] = True
    enabled["xdg-open"] = True
    sources_on = {getattr(b, "source", None) for b in feature_binds(enabled)}
    assert str(home / ".local") in sources_on
    assert str(home / ".cache") in sources_on
    assert "/usr/libexec/flatpak-xdg-utils/xdg-open" in sources_on


def test_user_feature_shares_locale_and_term() -> None:
    enabled = {name: False for name in FEATURE_NAMES}
    names_off = feature_env_var_names(enabled)
    assert "LANG" not in names_off
    assert "TERM" not in names_off
    assert "EDITOR" not in names_off
    assert "HOME" in names_off  # base

    enabled["user"] = True
    names_on = feature_env_var_names(enabled)
    assert "LANG" in names_on
    assert "LC_NUMERIC" in names_on
    assert "LC_TIME" in names_on
    assert "COLORTERM" in names_on
    assert "EDITOR" in names_on
    assert "TERM" in names_on
    assert "TERMINFO" in names_on
    assert "TERM_PROGRAM" in names_on


def test_feature_env_vars_follow_topics() -> None:
    enabled = {name: False for name in FEATURE_NAMES}
    enabled["python"] = True
    names = feature_env_var_names(enabled)
    assert "VIRTUAL_ENV" in names
    assert "DOCKER_HOST" not in names
    assert "DBUS_SESSION_BUS_ADDRESS" not in names
    assert "LANG" not in names
    assert "TERM" not in names
    assert "HOME" in names  # base


def test_dbus_and_dbus_proxy_conflict() -> None:
    registry = load_feature_registry({})
    assert "dbus-proxy" in registry["dbus"].conflicts_with
    assert "dbus" in registry["dbus-proxy"].conflicts_with


def test_check_feature_requirements_reports_missing_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "buddelkiste.features.which",
        lambda name: None if name in {"ssh-agent", "xdg-dbus-proxy"} else f"/bin/{name}",
    )
    enabled = {name: False for name in FEATURE_NAMES}
    enabled["ssh"] = True
    enabled["dbus-proxy"] = True
    with pytest.raises(click.ClickException, match="Missing required executables") as excinfo:
        check_feature_requirements(enabled, {})
    message = str(excinfo.value)
    assert "ssh: ssh-agent" in message
    assert "dbus-proxy: xdg-dbus-proxy" in message


def test_format_features_help_lists_topics() -> None:
    text = format_features_help()
    assert "cursor" in text
    assert "python" in text
    assert "rust" in text
    assert "gui" in text
    assert "xdg-open" in text
    assert "user" in text
    assert "default: on" in text  # user
    assert "default: off" in text
    assert "buddelkiste.features:CURSOR" in text
    assert "buddelkiste.features:PYTHON" in text
    assert "buddelkiste.features:RUST" in text
    assert "buddelkiste.features:USER" in text
    assert "buddelkiste.features:DBUS_PROXY" in text
    assert "buddelkiste.features:HOME" not in text
    assert "buddelkiste.features:LOCALE" not in text
    assert "buddelkiste.features:TERM" not in text


def test_entry_point_features_include_builtins() -> None:
    loaded = load_entry_point_features()
    assert "cursor" in loaded
    assert "ssh" in loaded
    assert loaded["cursor"].origin.endswith(":CURSOR")


def test_third_party_entry_point_feature(monkeypatch: pytest.MonkeyPatch) -> None:
    from importlib.metadata import entry_points as real_entry_points

    class FakeEP:
        name = "labs"
        value = "acme.plugins:LABS"

        def load(self):
            return Feature(
                name="labs",
                description="Acme labs",
                default=False,
                env_vars=("LAB_TOKEN",),
            )

    class FakeEPs:
        def select(self, *, group):
            assert group == "buddelkiste.features"
            real = list(real_entry_points().select(group=group))
            return [*real, FakeEP()]

    monkeypatch.setattr("buddelkiste.features.entry_points", lambda: FakeEPs())
    clear_feature_caches()
    try:
        registry = load_entry_point_features()
        assert "labs" in registry
        assert registry["labs"].origin == "acme.plugins:LABS"
        assert "acme.plugins:LABS" in format_features_help()
        enabled = resolve_features({}, enable=["labs"])
        assert enabled["labs"] is True
    finally:
        monkeypatch.setattr("buddelkiste.features.entry_points", real_entry_points)
        clear_feature_caches()
