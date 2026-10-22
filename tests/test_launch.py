from __future__ import annotations

import os
import pwd
from importlib.metadata import version
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from buddelkiste.cli import append_executable_args, cli, resolve_launch_command
from buddelkiste.shims import install_shims


def test_resolve_launch_command_uses_args() -> None:
    assert resolve_launch_command(["/bin/echo", "hi"]) == ["/bin/echo", "hi"]


def test_resolve_launch_command_resolves_bare_name_past_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wrappers = tmp_path / "shims"
    real_dir = tmp_path / "bin"
    install_shims(["tool"], bin_dir=wrappers)
    real_dir.mkdir()
    real = real_dir / "tool"
    real.write_text("#!/bin/sh\n", encoding="utf-8")
    real.chmod(0o755)
    monkeypatch.setenv("PATH", f"{wrappers}:{real_dir}")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert resolve_launch_command(["tool", "--flag"]) == [str(real), "--flag"]


def test_resolve_launch_command_refuses_shim_path(tmp_path: Path) -> None:
    wrappers = tmp_path / "shims"
    install_shims(["tool"], bin_dir=wrappers)
    with pytest.raises(click.ClickException, match="PATH shim"):
        resolve_launch_command([str(wrappers / "tool")])


def test_resolve_launch_command_falls_back_to_shell() -> None:
    shell = pwd.getpwuid(os.getuid()).pw_shell
    assert resolve_launch_command([]) == [shell, "-si", "--"]


@pytest.mark.parametrize("help_arg", ["--help", "-h"])
def test_resolve_launch_command_help_exits(help_arg: str) -> None:
    @click.command(help="wrapper help")
    def dummy() -> None:
        pass

    with dummy.make_context("dummy", []), pytest.raises(SystemExit) as excinfo:
        resolve_launch_command([help_arg])
    assert excinfo.value.code == 0


def test_append_executable_args_by_basename() -> None:
    config = {
        "executables": {
            "cursor-agent": {"args": ["--force", "--yolo"]},
        }
    }
    assert append_executable_args(
        ["cursor-agent", "do-thing"], config, "cursor-agent"
    ) == ["cursor-agent", "do-thing", "--force", "--yolo"]
    assert append_executable_args(
        ["/opt/bin/cursor-agent", "x"], config, "/opt/bin/cursor-agent"
    ) == ["/opt/bin/cursor-agent", "x", "--force", "--yolo"]


def test_append_executable_args_matches_file_name_not_path() -> None:
    config = {
        "executables": {
            "/usr/bin/python": {"args": ["-u"]},
        }
    }
    for executable in ("/usr/bin/python", "/opt/python", "python"):
        assert append_executable_args(
            [executable, "app.py"], config, executable
        ) == [executable, "app.py", "-u"]
    assert append_executable_args(
        ["/usr/bin/python3", "app.py"], config, "/usr/bin/python3"
    ) == ["/usr/bin/python3", "app.py"]


def test_append_executable_args_file_name_first_key_wins() -> None:
    config = {
        "executables": {
            "python": {"args": ["-B"]},
            "/usr/bin/python": {"args": ["-u"]},
        }
    }
    assert append_executable_args(
        ["/usr/bin/python", "app.py"], config, "/usr/bin/python"
    ) == ["/usr/bin/python", "app.py", "-B"]


def test_append_executable_args_noop_without_config() -> None:
    assert append_executable_args(["echo", "hi"], {}, "echo") == ["echo", "hi"]
    assert append_executable_args(["echo"], {"executables": {}}, None) == ["echo"]


def test_append_executable_args_rejects_invalid() -> None:
    with pytest.raises(click.ClickException, match="list of strings"):
        append_executable_args(
            ["foo"],
            {"executables": {"foo": {"args": "not-a-list"}}},
            "foo",
        )
    with pytest.raises(click.ClickException, match="list of strings"):
        append_executable_args(
            ["foo"],
            {"executables": {"foo": {"args": [1]}}},
            "foo",
        )


def test_cli_group_help() -> None:
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "run" in result.output
    assert "list-features" in result.output
    assert "list-net-presets" in result.output
    assert "shims" in result.output
    assert "--version" in result.output


def test_cli_version() -> None:
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"bk, version {version('buddelkiste')}"


def test_cli_run_help_via_args() -> None:
    result = CliRunner().invoke(cli, ["run", "--help"])
    assert result.exit_code == 0
    assert "Run a command inside a bubblewrap sandbox" in result.output
    assert "--debug" in result.output
    assert "--debug-file" in result.output
