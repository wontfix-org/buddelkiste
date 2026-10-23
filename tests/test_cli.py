from __future__ import annotations

import json
import logging
import os
import pwd
import tomllib
from pathlib import Path

import pytest
from click.testing import CliRunner

from buddelkiste.cli import RWBindConfig, cli
from buddelkiste.network import NetworkConfig


@pytest.fixture
def prepared_cwd(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "buddelkiste.cli.get_binds",
        lambda config, enabled=None, **kwargs: [RWBindConfig(tmp_path)],
    )
    monkeypatch.setattr(
        "buddelkiste.cli.ensure_cwd_project",
        lambda config, **kwargs: config,
    )
    return tmp_path


@pytest.fixture
def fake_bwrap(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {"nets": [], "args": []}

    def fake_run(bwrap_args, net):
        captured["args"] = list(bwrap_args)
        captured["nets"].append(net)
        if bwrap_args[-2:] == ["/bin/echo", "hello"]:
            return 42
        return 0

    monkeypatch.setattr("buddelkiste.cli.run_bwrap", fake_run)
    return captured


def test_cli_runs_bwrap_with_command(
    prepared_cwd: Path,
    fake_bwrap,
) -> None:
    result = CliRunner().invoke(cli, ["run", "--no-feature", "ssh", "/bin/echo", "hello"])
    assert result.exit_code == 42, result.output
    args = fake_bwrap["args"]
    assert args[:1] == ["bwrap"]
    assert args[args.index("--uid") + 1] == str(os.getuid())
    assert args[args.index("--gid") + 1] == str(os.getgid())
    assert args[args.index("--cap-drop") + 1] == "ALL"
    name = pwd.getpwuid(os.getuid()).pw_name
    dash = args.index("--")
    assert dash > args.index("--clearenv")
    assert args[dash - 6 : dash] == [
        "--setenv",
        "USER",
        name,
        "--setenv",
        "LOGNAME",
        name,
    ]
    assert args[-3:] == ["--", "/bin/echo", "hello"]
    assert fake_bwrap["nets"][0].mode == "filter"
    assert fake_bwrap["nets"][0].backend == "pasta"
    assert "10.0.0.0/8" in fake_bwrap["nets"][0].deny
    assert "127.0.0.0/8" in fake_bwrap["nets"][0].deny
    assert "SSH_AUTH_SOCK" not in fake_bwrap["args"]


def test_cli_shell_fallback_when_no_args(
    prepared_cwd: Path,
    fake_bwrap,
) -> None:
    result = CliRunner().invoke(cli, ["run", "--no-feature", "ssh"])
    assert result.exit_code == 0, result.output
    shell = pwd.getpwuid(os.getuid()).pw_shell
    assert fake_bwrap["args"][-4:] == ["--", shell, "-si", "--"]


def test_cli_forwards_help_to_command(
    prepared_cwd: Path,
    fake_bwrap,
) -> None:
    result = CliRunner().invoke(
        cli, ["run", "--no-feature", "ssh", "/bin/echo", "--help"]
    )
    assert result.exit_code == 0, result.output
    assert fake_bwrap["args"][-3:] == ["--", "/bin/echo", "--help"]
    assert "Run a command inside a bubblewrap sandbox" not in result.output


def test_cli_list_features(tmp_config: Path) -> None:
    tmp_config.write_text(
        "[feature.zig]\n"
        'description = "Zig toolchain cache"\n'
        'env = ["ZIG_GLOBAL_CACHE_DIR"]\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(cli, ["list-features"])
    assert result.exit_code == 0
    assert "cursor" in result.output
    assert "python" in result.output
    assert "rust" in result.output
    assert "buddelkiste.features:CURSOR" in result.output
    assert "buddelkiste.features:RUST" in result.output
    assert "zig" in result.output
    assert "config:[feature.zig]" in result.output


def test_cli_info_defaults(tmp_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli, ["info"])
    assert result.exit_code == 0, result.output
    assert f"config: {tmp_config}" in result.output
    assert f"cwd: {tmp_path.resolve()}" in result.output
    assert "project: (none)" in result.output
    assert "executable: (none)" in result.output
    assert "shims: true" in result.output
    assert "  - user\n" in result.output
    assert "  - python\n" not in result.output
    assert "  mode: filter" in result.output
    assert "  backend: pasta" in result.output
    with pytest.raises(tomllib.TOMLDecodeError):
        tomllib.loads(result.output)


def test_cli_info_merges_global_executable_and_project(
    tmp_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.chdir(repo)
    tmp_config.write_text(
        'features = ["user", "git"]\n'
        "\n"
        "[network]\n"
        'mode = "filter"\n'
        'allow = ["1.1.1.1/32"]\n'
        "\n"
        "[dbus_proxy]\n"
        'talk = ["org.foo.Bar"]\n'
        "\n"
        "[feature.zig]\n"
        'description = "Zig toolchain cache"\n'
        "\n"
        "[executables.python]\n"
        "features = { python = true }\n"
        'args = ["-u"]\n'
        "\n"
        "[executables.python.network]\n"
        'mode = "none"\n'
        "\n"
        "[[projects]]\n"
        f"path = {json.dumps(str(repo))}\n"
        "features = { rust = true }\n"
        "\n"
        "[[binds]]\n"
        'source = "/tmp"\n'
        'mode = "ro"\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(cli, ["info", "/usr/bin/python"])
    assert result.exit_code == 0, result.output
    assert f"project: {repo.resolve()}" in result.output
    assert "executable: /usr/bin/python" in result.output
    assert "  - -u\n" in result.output
    assert "  - user\n" in result.output
    assert "  - git\n" in result.output
    assert "  - python\n" in result.output
    assert "  - rust\n" in result.output
    assert "  - cursor\n" not in result.output
    assert "  mode: none" in result.output
    assert "  - org.foo.Bar\n" in result.output
    assert "  - /tmp (ro)\n" in result.output
    assert "Zig toolchain cache" not in result.output
    with pytest.raises(tomllib.TOMLDecodeError):
        tomllib.loads(result.output)


def test_cli_config_show_defaults(
    tmp_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli, ["config", "show"])
    assert result.exit_code == 0, result.output
    data = tomllib.loads(result.output)
    assert data["features"]["user"] is True
    assert data["features"]["python"] is False
    assert data["network"]["mode"] == "filter"
    assert data["network"]["backend"] == "pasta"
    assert data["shims"] is True
    assert f"config: {tmp_config}" in result.output
    assert f"cwd: {tmp_path.resolve()}" in result.output
    assert "project: (none)" in result.output
    assert "executable: (none)" in result.output


def test_cli_config_show_merges_global_executable_and_project(
    tmp_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.chdir(repo)
    tmp_config.write_text(
        'features = ["user", "git"]\n'
        "\n"
        "[network]\n"
        'mode = "filter"\n'
        'allow = ["1.1.1.1/32"]\n'
        "\n"
        "[dbus_proxy]\n"
        'talk = ["org.foo.Bar"]\n'
        "\n"
        "[feature.zig]\n"
        'description = "Zig toolchain cache"\n'
        "\n"
        "[executables.python]\n"
        "features = { python = true }\n"
        "\n"
        "[executables.python.network]\n"
        'mode = "none"\n'
        "\n"
        "[[projects]]\n"
        f"path = {json.dumps(str(repo))}\n"
        "features = { rust = true }\n"
        "\n"
        "[[binds]]\n"
        'source = "/tmp"\n'
        'mode = "ro"\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(cli, ["config", "show", "/usr/bin/python"])
    assert result.exit_code == 0, result.output
    data = tomllib.loads(result.output)
    assert data["features"]["user"] is True
    assert data["features"]["git"] is True
    assert data["features"]["python"] is True
    assert data["features"]["rust"] is True
    assert data["features"]["cursor"] is False
    assert data["network"]["mode"] == "none"
    assert data["dbus_proxy"]["talk"] == ["org.foo.Bar"]
    assert data["feature"]["zig"]["description"] == "Zig toolchain cache"
    assert data["binds"] == [{"source": "/tmp", "mode": "ro"}]
    assert "executables" not in data
    assert "projects" not in data
    assert f"project: {repo.resolve()}" in result.output
    assert "executable: /usr/bin/python" in result.output


def test_cli_fails_early_when_feature_command_missing(
    prepared_cwd: Path,
    fake_bwrap,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "buddelkiste.features.which",
        lambda name: None if name == "xdg-dbus-proxy" else f"/usr/bin/{name}",
    )
    result = CliRunner().invoke(
        cli,
        ["run", "--no-feature", "ssh", "--feature", "dbus-proxy", "/bin/true"],
    )
    assert result.exit_code != 0
    assert "Missing required executables for enabled features" in result.output
    assert "dbus-proxy: xdg-dbus-proxy" in result.output
    assert fake_bwrap["args"] == []


def test_cli_disables_feature_via_flag(
    prepared_cwd: Path,
    fake_bwrap,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VIRTUAL_ENV", "/tmp/venv")

    result = CliRunner().invoke(
        cli, ["run", "--no-feature", "python", "--no-feature", "ssh", "/bin/true"]
    )
    assert result.exit_code == 0, result.output
    assert "VIRTUAL_ENV" not in fake_bwrap["args"]


def test_cli_uses_per_executable_features(
    prepared_cwd: Path,
    tmp_config: Path,
    fake_bwrap,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_config.write_text(
        'features = ["git"]\n\n'
        '[executables."/bin/true"]\n'
        'features = ["python"]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("VIRTUAL_ENV", "/tmp/venv")
    monkeypatch.setenv("DOCKER_HOST", "unix:///tmp/docker.sock")

    result = CliRunner().invoke(cli, ["run", "--no-feature", "ssh", "/bin/true"])
    assert result.exit_code == 0, result.output
    assert "VIRTUAL_ENV" in fake_bwrap["args"]
    assert "DOCKER_HOST" not in fake_bwrap["args"]


def test_cli_appends_per_executable_args(
    prepared_cwd: Path,
    tmp_config: Path,
    fake_bwrap,
) -> None:
    tmp_config.write_text(
        '[executables."/bin/echo"]\n'
        'args = ["from-config"]\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        cli, ["run", "--no-feature", "ssh", "/bin/echo", "hello"]
    )
    assert result.exit_code == 0, result.output
    assert fake_bwrap["args"][-4:] == ["--", "/bin/echo", "hello", "from-config"]


def test_cli_network_filter_flags(
    prepared_cwd: Path,
    fake_bwrap,
) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "run",
            "--no-feature",
            "ssh",
            "--network",
            "filter",
            "--net-policy",
            "deny",
            "--net-allow",
            "1.1.1.1/32",
            "--net-deny",
            "169.254.169.254/32",
            "/bin/true",
        ],
    )
    assert result.exit_code == 0, result.output
    net = fake_bwrap["nets"][0]
    assert isinstance(net, NetworkConfig)
    assert net.mode == "filter"
    assert net.backend == "pasta"
    assert net.policy == "deny"
    assert net.allow == ["1.1.1.1/32"]
    assert "169.254.169.254/32" in net.deny
    assert "10.0.0.0/8" in net.deny  # default internal preset
    assert "127.0.0.0/8" in net.deny  # default localhost preset


def test_cli_net_backend_from_config(
    prepared_cwd: Path, tmp_config: Path, fake_bwrap
) -> None:
    tmp_config.write_text(
        '[network]\nbackend = "slirp4netns"\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        cli, ["run", "--no-feature", "ssh", "/bin/true"]
    )
    assert result.exit_code == 0, result.output
    assert fake_bwrap["nets"][0].backend == "slirp4netns"


def test_cli_net_backend_flag(prepared_cwd: Path, fake_bwrap) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "run",
            "--no-feature",
            "ssh",
            "--net-backend",
            "slirp",
            "/bin/true",
        ],
    )
    assert result.exit_code == 0, result.output
    assert fake_bwrap["nets"][0].backend == "slirp4netns"


def test_cli_net_allow_implies_filter(prepared_cwd: Path, fake_bwrap) -> None:
    result = CliRunner().invoke(
        cli,
        ["run", "--no-feature", "ssh", "--net-allow", "1.1.1.1/32", "/bin/true"],
    )
    assert result.exit_code == 0, result.output
    assert fake_bwrap["nets"][0].mode == "filter"
    assert fake_bwrap["nets"][0].allow == ["1.1.1.1/32"]


def test_cli_network_none_mode(prepared_cwd: Path, fake_bwrap) -> None:
    result = CliRunner().invoke(
        cli, ["run", "--no-feature", "ssh", "--network", "none", "/bin/true"]
    )
    assert result.exit_code == 0, result.output
    assert fake_bwrap["nets"][0].mode == "none"


def test_cli_list_net_presets(tmp_config: Path) -> None:
    tmp_config.write_text(
        "[network.presets]\ncorp = [\"10.50.0.0/16\"]\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(cli, ["list-net-presets"])
    assert result.exit_code == 0
    assert "private" in result.output
    assert "internal" in result.output
    assert "localhost" in result.output
    assert "metadata" in result.output
    assert "corp" in result.output
    assert "custom" in result.output


def test_cli_debug_logs_wildcard_policy(
    prepared_cwd: Path,
    fake_bwrap,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BUDDELKISTE_DEBUG", raising=False)
    with caplog.at_level(logging.DEBUG, logger="buddelkiste.cli"):
        result = CliRunner().invoke(
            cli,
            [
                "run",
                "--debug",
                "--no-feature",
                "ssh",
                "--net-allow",
                "*.example.com",
                "--net-deny",
                "exact.example",
                "/bin/true",
            ],
        )
    assert result.exit_code == 0, result.output
    assert "network wildcards allow=['*.example.com'] deny=[]" in caplog.text
    assert "allow_hosts=['*.example.com']" in caplog.text
    assert "deny_hosts=['exact.example']" in caplog.text
    assert os.environ.get("BUDDELKISTE_DEBUG") == "1"
    assert os.environ.get("BUDDELKISTE_DEBUG_FILE") is None
    assert os.environ.get("BUDDELKISTE_DEBUG_STDERR") is None


def test_cli_debug_file_writes_log_without_stderr(
    prepared_cwd: Path,
    fake_bwrap,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("BUDDELKISTE_DEBUG", raising=False)
    monkeypatch.delenv("BUDDELKISTE_DEBUG_FILE", raising=False)
    monkeypatch.delenv("BUDDELKISTE_DEBUG_STDERR", raising=False)
    log_path = tmp_path / "logs" / "bk-debug.log"
    result = CliRunner().invoke(
        cli,
        ["run", "--debug-file", str(log_path), "--network", "none", "/bin/true"],
    )
    assert result.exit_code == 0, result.output
    text = log_path.read_text(encoding="utf-8")
    assert "DEBUG buddelkiste: Running bwrap:" in text
    assert "DEBUG buddelkiste.cli: network mode=none" in text
    assert "DEBUG buddelkiste" not in result.output
    assert os.environ["BUDDELKISTE_DEBUG"] == "1"
    assert os.environ["BUDDELKISTE_DEBUG_FILE"] == str(log_path.resolve())
    assert os.environ["BUDDELKISTE_DEBUG_STDERR"] == "0"

    with log_path.open("a", encoding="utf-8") as handle:
        handle.write("STALE\n")
    again = CliRunner().invoke(
        cli,
        ["run", "--debug-file", str(log_path), "--network", "none", "/bin/true"],
    )
    assert again.exit_code == 0, again.output
    replaced = log_path.read_text(encoding="utf-8")
    assert "STALE" not in replaced
    assert "DEBUG buddelkiste.cli: network mode=none" in replaced


def test_cli_debug_file_with_debug_keeps_stderr(
    prepared_cwd: Path,
    fake_bwrap,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("BUDDELKISTE_DEBUG", raising=False)
    log_path = tmp_path / "bk-debug.log"
    with caplog.at_level(logging.DEBUG, logger="buddelkiste"):
        result = CliRunner().invoke(
            cli,
            [
                "run",
                "--debug",
                "--debug-file",
                str(log_path),
                "--network",
                "none",
                "/bin/true",
            ],
        )
    assert result.exit_code == 0, result.output
    text = log_path.read_text(encoding="utf-8")
    assert "DEBUG buddelkiste.cli: network mode=none" in text
    assert "network mode=none" in caplog.text
    assert os.environ["BUDDELKISTE_DEBUG_STDERR"] == "1"


def test_cli_net_allow_preset(prepared_cwd: Path, fake_bwrap) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "run",
            "--no-feature",
            "ssh",
            "--network",
            "filter",
            "--net-allow-preset",
            "metadata",
            "/bin/true",
        ],
    )
    assert result.exit_code == 0, result.output
    net = fake_bwrap["nets"][0]
    assert "169.254.169.254/32" in net.allow
    assert "metadata" in net.allow_presets


def test_cli_net_deny_preset(prepared_cwd: Path, fake_bwrap) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "run",
            "--no-feature",
            "ssh",
            "--network",
            "filter",
            "--net-deny-preset",
            "metadata",
            "/bin/true",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "169.254.169.254/32" in fake_bwrap["nets"][0].deny


def test_cli_custom_net_deny_preset(
    prepared_cwd: Path,
    tmp_config: Path,
    fake_bwrap,
) -> None:
    tmp_config.write_text(
        "[network.presets]\ncorp = [\"10.50.0.0/16\", \"blocked.example\"]\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        cli,
        [
            "run",
            "--no-feature",
            "ssh",
            "--network",
            "filter",
            "--net-deny-preset",
            "corp",
            "/bin/true",
        ],
    )
    assert result.exit_code == 0, result.output
    net = fake_bwrap["nets"][0]
    assert "10.50.0.0/16" in net.deny
    assert "blocked.example" in net.deny_hosts
