from __future__ import annotations

import stat
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from buddelkiste.cli import cli
from buddelkiste.shims import (
    ENV_MARKER,
    HOOK_BEGIN,
    HOOK_END,
    SHIM_MARKER,
    SHIM_MARKER_PREFIX,
    check_shims,
    home_relative_shell_path,
    install_shim_hook,
    install_shims,
    install_shims_from_config,
    is_our_shim,
    list_shim_names,
    list_shims,
    render_rc_include,
    render_shim,
    render_shim_env,
    resolve_run_executable,
    resolve_shim_target,
    shim_decisions_from_config,
    shim_dir,
    shim_dir_on_path,
    shim_env_path,
    shim_names_from_config,
)


def test_shim_dir_default(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    assert shim_dir() == home / ".local" / "share" / "buddelkiste" / "shims"
    assert shim_env_path() == home / ".local" / "share" / "buddelkiste" / "shims.sh"


def test_shim_dir_honors_xdg_data_home(monkeypatch, tmp_path: Path) -> None:
    custom = tmp_path / "data"
    monkeypatch.setenv("XDG_DATA_HOME", str(custom))
    assert shim_dir() == custom / "buddelkiste" / "shims"
    assert shim_env_path() == custom / "buddelkiste" / "shims.sh"


def test_home_relative_shell_path_uses_home(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    target = home / ".local" / "share" / "buddelkiste" / "shims.sh"
    target.parent.mkdir(parents=True)
    target.write_text("", encoding="utf-8")
    assert home_relative_shell_path(target, home=home) == (
        '"$HOME/.local/share/buddelkiste/shims.sh"'
    )


def test_home_relative_shell_path_outside_home(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "elsewhere" / "shims.sh"
    target.parent.mkdir()
    target.write_text("", encoding="utf-8")
    quoted = home_relative_shell_path(target, home=home)
    assert "$HOME" not in quoted
    assert str(target.resolve()) in quoted


def test_shim_names_from_config_dedupes_basenames() -> None:
    names = shim_names_from_config(
        {
            "executables": {
                "cursor-agent": {},
                "/opt/bin/cursor-agent": {"features": ["cursor"]},
                "/usr/bin/python": {},
            }
        }
    )
    assert names == ["cursor-agent", "python"]


def test_shim_names_respects_global_and_per_executable_toggles() -> None:
    assert shim_names_from_config(
        {
            "shims": False,
            "executables": {
                "a": {},
                "b": {"shim": True},
                "c": {"shim": False},
            },
        }
    ) == ["b"]

    assert shim_names_from_config(
        {
            "executables": {
                "a": {},
                "b": {"shim": False},
            },
        }
    ) == ["a"]

    decisions = shim_decisions_from_config(
        {
            "shims": True,
            "executables": {"tool": {"shim": False}},
        }
    )
    assert decisions == {"tool": False}


def test_shim_toggle_rejects_non_bool() -> None:
    with pytest.raises(click.ClickException, match="shims"):
        shim_names_from_config({"shims": "yes", "executables": {"a": {}}})
    with pytest.raises(click.ClickException, match="shim"):
        shim_names_from_config({"executables": {"a": {"shim": 1}}})


def test_install_from_config_removes_disabled(tmp_path: Path) -> None:
    wrappers = tmp_path / "bin"
    install_shims(["keep", "drop"], bin_dir=wrappers)
    assert (wrappers / "drop").exists()

    results = install_shims_from_config(
        {
            "executables": {
                "keep": {},
                "drop": {"shim": False},
            }
        },
        bin_dir=wrappers,
    )
    by_name = {r.name: r for r in results}
    assert by_name["drop"].action == "removed"
    assert not (wrappers / "drop").exists()
    assert by_name["keep"].action == "unchanged"
    assert is_our_shim(wrappers / "keep")


def test_cli_shims_respect_global_off(
    tmp_path: Path,
    tmp_config: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)

    tmp_config.write_text(
        "shims = false\n\n"
        "[executables.cursor-agent]\n"
        'features = ["cursor"]\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(cli, ["shims", "install"])
    assert result.exit_code == 0, result.output
    assert "disabled" in result.output
    assert "Open a new shell to activate the shims." in result.output
    assert not (home / ".local" / "share" / "buddelkiste" / "shims" / "cursor-agent").exists()
    assert (home / ".local" / "share" / "buddelkiste" / "shims.sh").is_file()

    check = CliRunner().invoke(cli, ["shims", "check"])
    assert check.exit_code == 0, check.output
    assert "disabled" in check.output


def test_render_shim_has_marker_and_bk_run() -> None:
    body = render_shim()
    assert body.startswith("#!/bin/sh\n")
    assert SHIM_MARKER in body
    assert 'exec "$bk" run "$real" "$@"' in body
    assert "command -v" in body  # used to locate bk
    assert '[ -f "$candidate" ]' in body


def test_render_shim_env_uses_home_and_quiet_check(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    wrappers = home / ".local" / "share" / "buddelkiste" / "shims"
    wrappers.mkdir(parents=True)
    body = render_shim_env(shim_directory=wrappers, home=home)
    assert ENV_MARKER in body
    assert '_bk_shims="$HOME/.local/share/buddelkiste/shims"' in body
    assert "case $- in" in body
    assert "bk shims check --quiet || true" in body
    assert "check --quiet >/dev/null" not in body
    assert "check --quiet 2>" not in body


def test_render_rc_include_uses_home(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    env_path = home / ".local" / "share" / "buddelkiste" / "shims.sh"
    env_path.parent.mkdir(parents=True)
    env_path.write_text("", encoding="utf-8")
    block = render_rc_include(env_path, home=home)
    assert block.startswith(HOOK_BEGIN)
    assert block.rstrip().endswith(HOOK_END)
    assert 'if [ -r "$HOME/.local/share/buddelkiste/shims.sh" ]; then' in block
    assert '. "$HOME/.local/share/buddelkiste/shims.sh"' in block
    assert str(home) not in block


def test_is_our_shim_detects_marker(tmp_path: Path) -> None:
    ours = tmp_path / "tool"
    ours.write_text(render_shim(), encoding="utf-8")
    foreign = tmp_path / "other"
    foreign.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    assert is_our_shim(ours) is True
    assert is_our_shim(foreign) is False
    assert is_our_shim(tmp_path / "missing") is False
    binary = tmp_path / "elf"
    binary.write_bytes(b"\x7fELF\x02\x01\x01\x00\xf8")
    assert is_our_shim(binary) is False


def test_install_creates_executable_shims(tmp_path: Path) -> None:
    wrappers = tmp_path / "bin"
    results = install_shims(["cursor-agent", "python"], bin_dir=wrappers)
    assert [r.action for r in results] == ["created", "created"]
    for name in ("cursor-agent", "python"):
        path = wrappers / name
        assert is_our_shim(path)
        assert path.stat().st_mode & stat.S_IXUSR
        assert SHIM_MARKER_PREFIX in path.read_text(encoding="utf-8")


def test_install_skips_foreign_and_updates_ours(tmp_path: Path) -> None:
    wrappers = tmp_path / "bin"
    wrappers.mkdir()
    foreign = wrappers / "python"
    foreign.write_text("#!/bin/sh\necho stock\n", encoding="utf-8")
    ours = wrappers / "cursor-agent"
    ours.write_text(
        "#!/bin/sh\n# buddelkiste-shim:0\nold\n",
        encoding="utf-8",
    )

    results = {r.name: r for r in install_shims(["python", "cursor-agent"], bin_dir=wrappers)}
    assert results["python"].action == "skipped"
    assert foreign.read_text(encoding="utf-8") == "#!/bin/sh\necho stock\n"
    assert results["cursor-agent"].action == "updated"
    assert is_our_shim(ours)
    assert SHIM_MARKER in ours.read_text(encoding="utf-8")

    again = install_shims(["cursor-agent"], bin_dir=wrappers)
    assert again[0].action == "unchanged"


def test_install_force_replaces_foreign_file_not_directory(tmp_path: Path) -> None:
    wrappers = tmp_path / "bin"
    wrappers.mkdir()
    foreign = wrappers / "python"
    foreign.write_text("#!/bin/sh\necho stock\n", encoding="utf-8")
    directory = wrappers / "node"
    directory.mkdir()

    skipped = install_shims(["python", "node"], bin_dir=wrappers, force=True)
    by_name = {r.name: r for r in skipped}
    assert by_name["python"].action == "updated"
    assert is_our_shim(foreign)
    assert foreign.stat().st_mode & stat.S_IXUSR
    assert by_name["node"].action == "skipped"
    assert directory.is_dir()


def test_install_force_replaces_symlink_without_touching_target(tmp_path: Path) -> None:
    wrappers = tmp_path / "bin"
    wrappers.mkdir()
    target = tmp_path / "real-python"
    original = "#!/bin/sh\necho stock\n"
    target.write_text(original, encoding="utf-8")
    link = wrappers / "python"
    link.symlink_to(target)

    skipped = install_shims(["python"], bin_dir=wrappers)
    assert skipped[0].action == "skipped"
    assert link.is_symlink()
    assert target.read_text(encoding="utf-8") == original

    forced = install_shims(["python"], bin_dir=wrappers, force=True)
    assert forced[0].action == "updated"
    assert not link.is_symlink()
    assert is_our_shim(link)
    assert target.read_text(encoding="utf-8") == original


def test_install_does_not_remove_foreign_file_when_disabled(tmp_path: Path) -> None:
    wrappers = tmp_path / "bin"
    wrappers.mkdir()
    foreign = wrappers / "python"
    foreign.write_text("#!/bin/sh\necho stock\n", encoding="utf-8")
    config = {"executables": {"python": {"shim": False}}}

    results = install_shims_from_config(config, bin_dir=wrappers, force=True)
    assert [r.action for r in results] == ["skipped"]
    assert foreign.read_text(encoding="utf-8") == "#!/bin/sh\necho stock\n"


def test_install_shim_hook_writes_snippet_and_existing_rc(
    monkeypatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    bashrc = home / ".bashrc"
    zshrc = home / ".zshrc"
    bashrc.write_text("# existing bash\n", encoding="utf-8")
    zshrc.write_text("# existing zsh\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)

    results = {r.name: r for r in install_shim_hook()}
    assert results["shims.sh"].action == "created"
    assert results[".bashrc"].action == "updated"
    assert results[".zshrc"].action == "updated"

    env_text = (home / ".local" / "share" / "buddelkiste" / "shims.sh").read_text(
        encoding="utf-8"
    )
    assert ENV_MARKER in env_text
    assert "$HOME/.local/share/buddelkiste/shims" in env_text
    assert "bk shims check --quiet || true" in env_text

    bash = bashrc.read_text(encoding="utf-8")
    assert bash.startswith("# existing bash\n")
    assert HOOK_BEGIN in bash
    assert '"$HOME/.local/share/buddelkiste/shims.sh"' in bash
    assert str(home) not in bash
    assert bash.count(HOOK_BEGIN) == 1

    again = {r.name: r for r in install_shim_hook()}
    assert again["shims.sh"].action == "unchanged"
    assert again[".bashrc"].action == "unchanged"
    assert again[".zshrc"].action == "unchanged"
    assert bashrc.read_text(encoding="utf-8").count(HOOK_BEGIN) == 1


def test_install_shim_hook_skips_foreign_snippet_unless_forced(
    monkeypatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    env_path = home / ".local" / "share" / "buddelkiste" / "shims.sh"
    env_path.parent.mkdir(parents=True)
    env_path.write_text("# not ours\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)

    results = {r.name: r for r in install_shim_hook()}
    assert results["shims.sh"].action == "skipped"
    assert env_path.read_text(encoding="utf-8") == "# not ours\n"

    forced = {r.name: r for r in install_shim_hook(force=True)}
    assert forced["shims.sh"].action == "updated"
    assert ENV_MARKER in env_path.read_text(encoding="utf-8")


def test_install_shim_hook_skips_missing_rc(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)

    results = {r.name: r for r in install_shim_hook()}
    assert set(results) == {"shims.sh"}
    assert not (home / ".bashrc").exists()
    assert not (home / ".zshrc").exists()


def test_check_ok_when_shim_first(tmp_path: Path) -> None:
    wrappers = tmp_path / "shims"
    real_dir = tmp_path / "real"
    install_shims(["tool"], bin_dir=wrappers)
    real_dir.mkdir()
    real = real_dir / "tool"
    real.write_text("#!/bin/sh\n", encoding="utf-8")
    real.chmod(0o755)

    path = f"{wrappers}:{real_dir}"
    assert check_shims(["tool"], bin_dir=wrappers, path_value=path) == []


def test_check_warns_when_original_first(tmp_path: Path) -> None:
    wrappers = tmp_path / "shims"
    real_dir = tmp_path / "real"
    install_shims(["tool"], bin_dir=wrappers)
    real_dir.mkdir()
    real = real_dir / "tool"
    real.write_text("#!/bin/sh\n", encoding="utf-8")
    real.chmod(0o755)

    path = f"{real_dir}:{wrappers}"
    issues = check_shims(["tool"], bin_dir=wrappers, path_value=path)
    assert len(issues) == 1
    assert issues[0].name == "tool"
    assert "bypass the sandbox" in issues[0].message
    assert str(real) in issues[0].message


def test_shim_dir_on_path(tmp_path: Path) -> None:
    wrappers = tmp_path / "shims"
    wrappers.mkdir()
    assert shim_dir_on_path(bin_dir=wrappers, path_value=f"{wrappers}:/usr/bin")
    assert not shim_dir_on_path(bin_dir=wrappers, path_value="/usr/bin")


def test_check_warns_when_bin_not_on_path(tmp_path: Path) -> None:
    wrappers = tmp_path / "shims"
    install_shims(["tool"], bin_dir=wrappers)
    issues = check_shims(["tool"], bin_dir=wrappers, path_value="/usr/bin")
    assert any(i.name == "*" for i in issues)
    assert any("not reachable via PATH" in i.message for i in issues)


def test_cli_shims_install_and_check(
    tmp_path: Path,
    tmp_config: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".bashrc").write_text("# rc\n", encoding="utf-8")
    wrappers = home / ".local" / "share" / "buddelkiste" / "shims"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("PATH", f"{wrappers}:/usr/bin")

    tmp_config.write_text(
        "[executables.cursor-agent]\nfeatures = [\"cursor\"]\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["shims", "install"])
    assert result.exit_code == 0, result.output
    assert "created" in result.output
    shim = wrappers / "cursor-agent"
    assert is_our_shim(shim)
    bashrc = (home / ".bashrc").read_text(encoding="utf-8")
    assert HOOK_BEGIN in bashrc
    assert "$HOME/.local/share/buddelkiste/shims.sh" in bashrc

    assert "Open a new shell" not in result.output

    check = runner.invoke(cli, ["shims", "check"])
    assert check.exit_code == 0, check.output
    assert "OK:" in check.output

    quiet = runner.invoke(cli, ["shims", "check", "-q"])
    assert quiet.exit_code == 0, quiet.output
    assert quiet.output == ""


def test_cli_shims_install_refuses_foreign_without_force(
    tmp_path: Path,
    tmp_config: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    wrappers = home / ".local" / "share" / "buddelkiste" / "shims"
    wrappers.mkdir(parents=True)
    foreign = wrappers / "cursor-agent"
    foreign.write_text("#!/bin/sh\necho stock\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("PATH", "/usr/bin")
    tmp_config.write_text(
        "[executables.cursor-agent]\nfeatures = [\"cursor\"]\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    refused = runner.invoke(cli, ["shims", "install"])
    assert refused.exit_code == 1, refused.output
    assert "Refusing to overwrite" in refused.output
    assert "--force" in refused.output
    assert foreign.read_text(encoding="utf-8") == "#!/bin/sh\necho stock\n"
    assert "skipped" in refused.output

    forced = runner.invoke(cli, ["shims", "install", "--force"])
    assert forced.exit_code == 0, forced.output
    assert "updated" in forced.output
    assert is_our_shim(foreign)


def test_cli_shims_install_force_still_refuses_directory(
    tmp_path: Path,
    tmp_config: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    blocked = home / ".local" / "share" / "buddelkiste" / "shims" / "cursor-agent"
    blocked.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("PATH", "/usr/bin")
    tmp_config.write_text(
        "[executables.cursor-agent]\nfeatures = [\"cursor\"]\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["shims", "install", "--force"])
    assert result.exit_code == 1, result.output
    assert "not regular files" in result.output
    assert blocked.is_dir()


def test_cli_shims_install_keeps_foreign_file_when_shim_disabled(
    tmp_path: Path,
    tmp_config: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    wrappers = home / ".local" / "share" / "buddelkiste" / "shims"
    wrappers.mkdir(parents=True)
    foreign = wrappers / "python"
    foreign.write_text("#!/bin/sh\necho stock\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("PATH", f"{wrappers}:/usr/bin")
    tmp_config.write_text(
        "[executables.python]\nshim = false\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["shims", "install", "--force"])
    assert result.exit_code == 0, result.output
    assert "not removed" in result.output
    assert foreign.read_text(encoding="utf-8") == "#!/bin/sh\necho stock\n"


def test_cli_shims_install_notes_new_shell_when_hook_not_loaded(
    tmp_path: Path,
    tmp_config: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".bashrc").write_text("# rc\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("PATH", "/usr/bin")
    tmp_config.write_text(
        "[executables.cursor-agent]\nfeatures = [\"cursor\"]\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["shims", "install"])
    assert result.exit_code == 0, result.output
    assert "Open a new shell to activate the shims." in result.output


def test_cli_shims_check_fails_on_shadow(
    tmp_path: Path,
    tmp_config: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    wrappers = home / ".local" / "share" / "buddelkiste" / "shims"
    real_dir = tmp_path / "elsewhere"
    real_dir.mkdir()
    real = real_dir / "cursor-agent"
    real.write_text("#!/bin/sh\n", encoding="utf-8")
    real.chmod(0o755)

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("PATH", f"{real_dir}:{wrappers}")

    tmp_config.write_text(
        "[executables.cursor-agent]\nfeatures = [\"cursor\"]\n",
        encoding="utf-8",
    )
    CliRunner().invoke(cli, ["shims", "install"])

    result = CliRunner().invoke(cli, ["shims", "check"])
    assert result.exit_code == 1
    assert "bypass the sandbox" in result.output

    quiet = CliRunner().invoke(cli, ["shims", "check", "--quiet"])
    assert quiet.exit_code == 1
    assert "bypass the sandbox" in quiet.output
    assert "OK:" not in quiet.output


def test_cli_shims_check_quiet_hides_empty_config(
    tmp_path: Path,
    tmp_config: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    tmp_config.write_text("", encoding="utf-8")

    quiet = CliRunner().invoke(cli, ["shims", "check", "-q"])
    assert quiet.exit_code == 0, quiet.output
    assert quiet.output == ""


def test_resolve_shim_target_skips_shim_dir(tmp_path: Path) -> None:
    wrappers = tmp_path / "shims"
    real_dir = tmp_path / "real"
    install_shims(["tool"], bin_dir=wrappers)
    real_dir.mkdir()
    real = real_dir / "tool"
    real.write_text("#!/bin/sh\n", encoding="utf-8")
    real.chmod(0o755)

    path = f"{wrappers}:{real_dir}"
    assert resolve_shim_target("tool", bin_dir=wrappers, path_value=path) == real
    assert resolve_shim_target("tool", bin_dir=wrappers, path_value=str(wrappers)) is None


def test_resolve_shim_target_skips_copied_shim(tmp_path: Path) -> None:
    wrappers = tmp_path / "shims"
    other = tmp_path / "also"
    real_dir = tmp_path / "real"
    install_shims(["tool"], bin_dir=wrappers)
    other.mkdir()
    copied = other / "tool"
    copied.write_text(render_shim(), encoding="utf-8")
    copied.chmod(0o755)
    real_dir.mkdir()
    real = real_dir / "tool"
    real.write_text("#!/bin/sh\n", encoding="utf-8")
    real.chmod(0o755)

    path = f"{other}:{real_dir}"
    assert resolve_shim_target("tool", bin_dir=wrappers, path_value=path) == real


def test_resolve_run_executable_skips_shim_dir(tmp_path: Path) -> None:
    wrappers = tmp_path / "shims"
    real_dir = tmp_path / "real"
    install_shims(["tool"], bin_dir=wrappers)
    real_dir.mkdir()
    real = real_dir / "tool"
    real.write_text("#!/bin/sh\n", encoding="utf-8")
    real.chmod(0o755)

    path = f"{wrappers}:{real_dir}"
    assert resolve_run_executable("tool", bin_dir=wrappers, path_value=path) == str(real)
    assert resolve_run_executable(str(real), bin_dir=wrappers, path_value=path) == str(real)


def test_resolve_run_executable_refuses_shim_path(tmp_path: Path) -> None:
    wrappers = tmp_path / "shims"
    install_shims(["tool"], bin_dir=wrappers)
    shim = wrappers / "tool"
    with pytest.raises(click.ClickException, match="PATH shim"):
        resolve_run_executable(str(shim), bin_dir=wrappers, path_value=str(wrappers))
    with pytest.raises(click.ClickException, match="PATH shim"):
        resolve_run_executable(
            "shims/tool",
            bin_dir=wrappers,
            path_value=str(wrappers),
            cwd=tmp_path,
        )


def test_list_shim_names_includes_leftover_installed(tmp_path: Path) -> None:
    wrappers = tmp_path / "shims"
    install_shims(["keep", "extra"], bin_dir=wrappers)
    names = list_shim_names(
        {"executables": {"keep": {}, "off": {"shim": False}}},
        bin_dir=wrappers,
    )
    assert names == ["keep", "extra"]
    listings = {row.name: row.target for row in list_shims(names, bin_dir=wrappers)}
    assert listings["keep"] is None
    assert listings["extra"] is None


def test_cli_shims_list_empty(
    tmp_path: Path,
    tmp_config: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    tmp_config.write_text("", encoding="utf-8")

    result = CliRunner().invoke(cli, ["shims", "list"])
    assert result.exit_code == 0, result.output
    assert "No shims." in result.output


def test_cli_shims_list_shows_real_executable(
    tmp_path: Path,
    tmp_config: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    real = real_dir / "cursor-agent"
    real.write_text("#!/bin/sh\n", encoding="utf-8")
    real.chmod(0o755)
    wrappers = home / ".local" / "share" / "buddelkiste" / "shims"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("PATH", f"{wrappers}:{real_dir}")
    tmp_config.write_text(
        "[executables.cursor-agent]\nfeatures = [\"cursor\"]\n"
        "[executables.missing]\nfeatures = []\n",
        encoding="utf-8",
    )
    CliRunner().invoke(cli, ["shims", "install"])

    result = CliRunner().invoke(cli, ["shims", "list"])
    assert result.exit_code == 0, result.output
    assert f"cursor-agent  {real}" in result.output
    assert "missing       -" in result.output
