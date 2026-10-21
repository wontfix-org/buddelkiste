"""dbus-proxy filter policy: config, CLI, and xdg-dbus-proxy argv."""

from __future__ import annotations

import logging
import socket
from pathlib import Path
from unittest.mock import MagicMock

import click
import pytest
from click.testing import CliRunner

from buddelkiste.cli import RWBindConfig, cli
from buddelkiste.dbus_proxy import (
    dbus_proxy_cli_context,
    dbus_proxy_command_args,
    resolve_dbus_proxy,
)
from buddelkiste.features import dbus_proxy_setup


def test_resolve_dbus_proxy_unfiltered_by_default() -> None:
    policy = resolve_dbus_proxy({})
    assert policy.filtered is False
    assert dbus_proxy_command_args(policy) == []


def test_resolve_dbus_proxy_config_enables_filter() -> None:
    policy = resolve_dbus_proxy(
        {
            "dbus_proxy": {
                "see": ["org.freedesktop.DBus"],
                "talk": [
                    "org.freedesktop.Notifications",
                    "org.freedesktop.portal.*",
                    "org.freedesktop.Notifications",
                ],
                "call": ["org.freedesktop.portal.*=*"],
                "broadcast": [
                    "org.freedesktop.portal.*=@/org/freedesktop/portal/*"
                ],
            }
        }
    )
    assert policy.filtered is True
    assert policy.see == ("org.freedesktop.DBus",)
    assert policy.talk == (
        "org.freedesktop.Notifications",
        "org.freedesktop.portal.*",
    )
    assert policy.call == ("org.freedesktop.portal.*=*",)
    assert policy.broadcast == (
        "org.freedesktop.portal.*=@/org/freedesktop/portal/*",
    )
    assert dbus_proxy_command_args(policy) == [
        "--filter",
        "--see=org.freedesktop.DBus",
        "--talk=org.freedesktop.Notifications",
        "--talk=org.freedesktop.portal.*",
        "--call=org.freedesktop.portal.*=*",
        "--broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*",
    ]


def test_resolve_dbus_proxy_empty_list_filters_without_rules() -> None:
    policy = resolve_dbus_proxy({"dbus_proxy": {"talk": [], "own": []}})
    assert policy.filtered is True
    assert dbus_proxy_command_args(policy) == ["--filter"]


def test_resolve_dbus_proxy_executable_replaces_key_and_cli_appends() -> None:
    config = {
        "dbus_proxy": {
            "see": ["org.global.See"],
            "talk": ["org.global.Talk"],
        },
        "executables": {
            "cursor-agent": {
                "dbus_proxy": {"talk": ["org.exec.Talk"]},
            }
        },
    }
    policy = resolve_dbus_proxy(
        config,
        executable="cursor-agent",
        talk=("org.cli.Talk", "org.exec.Talk"),
        own=("org.cli.Own",),
    )
    assert policy.see == ("org.global.See",)
    assert policy.talk == ("org.exec.Talk", "org.cli.Talk")
    assert policy.own == ("org.cli.Own",)


def test_resolve_dbus_proxy_cli_context() -> None:
    config = {"dbus_proxy": {"talk": ["org.config.Talk"]}}
    with dbus_proxy_cli_context(
        executable="/bin/true",
        call=("org.freedesktop.Notifications=org.freedesktop.Notifications.Notify",),
    ):
        policy = resolve_dbus_proxy(config)
    assert policy.talk == ("org.config.Talk",)
    assert policy.call == (
        "org.freedesktop.Notifications=org.freedesktop.Notifications.Notify",
    )


def test_resolve_dbus_proxy_explicit_executable_wins_over_cli_context() -> None:
    config = {
        "executables": {
            "cursor-agent": {"dbus_proxy": {"see": ["org.exec.See"]}},
        }
    }
    with dbus_proxy_cli_context(executable="other", talk=("org.cli.Talk",)):
        policy = resolve_dbus_proxy(config, executable="cursor-agent")
    assert policy.see == ("org.exec.See",)
    assert policy.talk == ("org.cli.Talk",)


def test_resolve_dbus_proxy_accepts_rule_shapes() -> None:
    policy = resolve_dbus_proxy(
        {
            "dbus_proxy": {
                "call": [
                    "org.freedesktop.DBus=",
                    "org.freedesktop.DBus=@/",
                    "org.freedesktop.portal.*=org.freedesktop.portal.*@/org/freedesktop/portal/*",
                    "org.example.App=org.example.App.DoThing@/org/example/App",
                ],
            }
        }
    )
    assert policy.call[1] == "org.freedesktop.DBus=@/"
    assert "org.freedesktop.portal.*" in policy.call[2]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("see", "*"),
        ("talk", "org.*"),
        ("own", ":1.5"),
        ("own", "org.foo."),
        ("call", "org.freedesktop.Notifications"),
        ("call", "*=*"),
        ("broadcast", "org.freedesktop.Notifications=Notify"),
        ("broadcast", "org.freedesktop.Notifications=org.foo.Bar@not-a-path"),
        ("call", "org.freedesktop.Notifications=org.foo.Bar@/org/foo/"),
        ("call", "org.freedesktop.Notifications=org.foo.Bar.Baz extra"),
        ("call", "org.freedesktop.Notifications=org.foo.Bar=Nope"),
        ("broadcast", "org.freedesktop.Notifications=org.*"),
        ("broadcast", "org.freedesktop.Notifications=@//*"),
        ("call", "org.freedesktop.Notifications=@/org/foo-bar"),
    ],
)
def test_resolve_dbus_proxy_rejects_bad_rules(key: str, value: str) -> None:
    with pytest.raises(click.ClickException):
        resolve_dbus_proxy({"dbus_proxy": {key: [value]}})


def test_resolve_dbus_proxy_rejects_unknown_key_and_bad_type() -> None:
    with pytest.raises(click.ClickException, match="unknown key"):
        resolve_dbus_proxy({"dbus_proxy": {"sees": ["org.foo.Bar"]}})
    with pytest.raises(click.ClickException, match="must be a list"):
        resolve_dbus_proxy({"dbus_proxy": {"talk": "org.foo.Bar"}})
    with pytest.raises(click.ClickException, match="must be a string"):
        resolve_dbus_proxy({"dbus_proxy": {"talk": [1]}})
    with pytest.raises(click.ClickException, match="must be a table"):
        resolve_dbus_proxy({"dbus_proxy": ["org.foo.Bar"]})


def test_dbus_proxy_setup_uses_resolved_rules(
    runtime_dir: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    (runtime_dir / "bus").touch()
    monkeypatch.setattr(
        "buddelkiste.features.which",
        lambda name: "/usr/bin/xdg-dbus-proxy" if name == "xdg-dbus-proxy" else None,
    )
    monkeypatch.setattr("buddelkiste.features.time.sleep", lambda _t: None)
    monkeypatch.setattr(
        "buddelkiste.cli.load_config",
        lambda: {
            "dbus_proxy": {
                "talk": ["org.freedesktop.Notifications"],
                "own": ["org.example.MyApp"],
            }
        },
    )

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
        return proc

    monkeypatch.setattr("buddelkiste.features.subprocess.Popen", fake_popen)

    with caplog.at_level(logging.DEBUG, logger="buddelkiste"), dbus_proxy_setup():
        cmd = captured["cmd"]
        assert "--filter" in cmd
        assert "--talk=org.freedesktop.Notifications" in cmd
        assert "--own=org.example.MyApp" in cmd
        assert "--see=*" not in cmd
        assert "Running xdg-dbus-proxy:" in caplog.text

    captured["listener"].close()


def test_cli_dbus_proxy_flags_reach_the_proxy(
    tmp_path: Path,
    runtime_dir: Path,
    tmp_config: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.chdir(tmp_path)
    (runtime_dir / "bus").touch()
    monkeypatch.setattr(
        "buddelkiste.cli.get_binds",
        lambda config, enabled=None, **kwargs: [RWBindConfig(tmp_path)],
    )
    monkeypatch.setattr("buddelkiste.cli.run_bwrap", lambda bwrap_args, net: 0)
    monkeypatch.setattr(
        "buddelkiste.features.which",
        lambda name: "/usr/bin/xdg-dbus-proxy" if name == "xdg-dbus-proxy" else f"/usr/bin/{name}",
    )
    monkeypatch.setattr("buddelkiste.features.time.sleep", lambda _t: None)

    tmp_config.write_text(
        "[dbus_proxy]\n"
        'see = ["org.config.See"]\n'
        'talk = ["org.config.Talk"]\n'
        "\n"
        "[executables.cursor-agent.dbus_proxy]\n"
        'talk = ["org.exec.Talk"]\n',
        encoding="utf-8",
    )

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
        return proc

    monkeypatch.setattr("buddelkiste.features.subprocess.Popen", fake_popen)

    result = CliRunner().invoke(
        cli,
        [
            "run",
            "--no-feature",
            "ssh",
            "--feature",
            "dbus-proxy",
            "--dbus-talk",
            "org.cli.Talk",
            "--dbus-call",
            "org.freedesktop.portal.*=*",
            "--dbus-broadcast",
            "org.freedesktop.portal.*=@/org/freedesktop/portal/*",
            "cursor-agent",
        ],
    )
    assert result.exit_code == 0, result.output
    cmd = captured["cmd"]
    assert "--filter" in cmd
    assert "--see=org.config.See" in cmd
    assert "--talk=org.exec.Talk" in cmd
    assert "--talk=org.cli.Talk" in cmd
    assert "--talk=org.config.Talk" not in cmd
    assert "--call=org.freedesktop.portal.*=*" in cmd
    assert "--broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*" in cmd
    captured["listener"].close()


def test_cli_dbus_proxy_rejects_invalid_name(
    tmp_path: Path,
    runtime_dir: Path,
    tmp_config: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.chdir(tmp_path)
    (runtime_dir / "bus").touch()
    monkeypatch.setattr(
        "buddelkiste.cli.get_binds",
        lambda config, enabled=None, **kwargs: [RWBindConfig(tmp_path)],
    )
    monkeypatch.setattr("buddelkiste.cli.run_bwrap", lambda bwrap_args, net: 0)
    monkeypatch.setattr(
        "buddelkiste.features.which",
        lambda name: "/usr/bin/xdg-dbus-proxy" if name == "xdg-dbus-proxy" else f"/usr/bin/{name}",
    )

    result = CliRunner().invoke(
        cli,
        [
            "run",
            "--no-feature",
            "ssh",
            "--feature",
            "dbus-proxy",
            "--dbus-talk",
            "*",
            "/bin/true",
        ],
    )
    assert result.exit_code != 0
    assert "not a valid D-Bus well-known name" in result.output
