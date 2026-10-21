"""Coverage for feature binds, SSH/dbus startup failures, and config validation."""

from __future__ import annotations

import logging
import socket
from importlib.metadata import entry_points as real_entry_points
from pathlib import Path
from unittest.mock import MagicMock

import click
import pytest

from buddelkiste.features import (
    ENTRY_POINT_GROUP,
    Feature,
    SshAgent,
    _bind_from_parts,
    asdf_binds,
    base_binds,
    bind_from_spec,
    binds_from_spec,
    clear_feature_caches,
    dbus_proxy_setup,
    docker_binds,
    docker_instance_feature_setup,
    feature_names,
    find_sandbox_ssh_key,
    git_binds,
    google_binds,
    gui_binds,
    java_binds,
    load_entry_point_features,
    load_feature_registry,
    lookup_executable_config,
    lookup_project_config,
    node_binds,
    nvim_binds,
    parse_toml_feature,
    resolve_features,
    ssh_setup,
)


def test_runtime_dir_must_be_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    with pytest.raises(click.ClickException, match="XDG_RUNTIME_DIR is not set"):
        base_binds()


def test_remaining_topic_binds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))

    node_sources = {bind.source for bind in node_binds()}
    assert str(home / ".nvm") in node_sources
    assert str(home / ".npm") in node_sources
    assert str(home / ".bun") in node_sources

    asdf_sources = {bind.source for bind in asdf_binds()}
    assert str(home / ".asdf") in asdf_sources
    assert str(home / ".tool-versions") in asdf_sources

    git_sources = {bind.source for bind in git_binds()}
    assert str(home / ".gitconfig") in git_sources
    assert str(home / ".config/git") in git_sources

    assert {bind.source for bind in google_binds()} == {"/opt/google"}
    assert {bind.source for bind in nvim_binds()} == {str(home / "nvim")}
    assert {bind.source for bind in java_binds()} == {
        "/etc/java-17-openjdk",
        "/etc/java-21-openjdk",
    }


def test_docker_binds_follow_the_daemon_socket(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    sock = runtime_dir / "docker.sock"
    monkeypatch.setenv("DOCKER_HOST", f"unix://{sock}")
    sources = {bind.source for bind in docker_binds()}
    assert sources == {str(home / ".docker"), str(sock)}

    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    sources = {bind.source for bind in docker_binds()}
    assert sources == {str(home / ".docker")}

    monkeypatch.delenv("DOCKER_HOST")
    sources = {bind.source for bind in docker_binds()}
    assert sources == {str(home / ".docker"), "/var/run/docker.sock"}

    monkeypatch.setenv("DOCKER_HOST", "unix:///run/user/docker.sock")
    monkeypatch.delenv("XDG_RUNTIME_DIR")
    sources = {bind.source for bind in docker_binds()}
    assert sources == {str(home / ".docker")}


def test_gui_binds_add_wayland_and_xauthority(
    runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.delenv("XAUTHORITY", raising=False)
    sources = {bind.source for bind in gui_binds()}
    assert "/dev/dri" in sources
    assert "/etc/fonts" in sources
    assert "/tmp/.X11-unix" in sources
    assert str(runtime_dir / "wayland-0") not in sources

    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.setenv("XAUTHORITY", "/tmp/xauth")
    sources = {bind.source for bind in gui_binds()}
    assert str(runtime_dir / "wayland-0") in sources
    assert "/tmp/xauth" in sources


def test_dbus_proxy_requires_session_bus(runtime_dir: Path) -> None:
    with pytest.raises(click.ClickException, match="session bus socket"), dbus_proxy_setup():
        pass


@pytest.mark.parametrize(
    ("payload", "detail"),
    [
        (b"proxy failed\n", "proxy failed"),
        (b"   ", ""),
        (None, ""),
    ],
)
def test_dbus_proxy_setup_reports_early_exit(
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes | None,
    detail: str,
) -> None:
    (runtime_dir / "bus").touch()
    monkeypatch.setattr(
        "buddelkiste.features.which",
        lambda name: "/usr/bin/xdg-dbus-proxy" if name == "xdg-dbus-proxy" else None,
    )
    monkeypatch.setattr("buddelkiste.features.time.sleep", lambda _t: None)
    monkeypatch.setattr("buddelkiste.cli.load_config", dict)
    if payload is None:
        stderr = None
    else:
        stderr = MagicMock()
        stderr.read.return_value = payload

    def fake_popen(*_args, **_kwargs):
        proc = MagicMock()
        proc.poll.return_value = 1
        proc.wait.return_value = 0
        proc.stderr = stderr
        return proc

    monkeypatch.setattr("buddelkiste.features.subprocess.Popen", fake_popen)
    with (
        pytest.raises(click.ClickException, match="exited during startup") as excinfo,
        dbus_proxy_setup(),
    ):
        pass
    message = str(excinfo.value)
    if detail:
        assert detail in message
    else:
        assert message == "xdg-dbus-proxy exited during startup."


def test_dbus_proxy_setup_waits_until_the_socket_appears(
    runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (runtime_dir / "bus").touch()
    monkeypatch.setattr(
        "buddelkiste.features.which",
        lambda name: "/usr/bin/xdg-dbus-proxy" if name == "xdg-dbus-proxy" else None,
    )
    monkeypatch.setattr("buddelkiste.cli.load_config", dict)
    listeners: list[socket.socket] = []
    pending: list[str] = []

    def fake_sleep(_seconds: float) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(pending.pop(0))
        listeners.append(listener)

    def fake_popen(args, **_kwargs):
        pending.append(args[2])
        proc = MagicMock()
        proc.poll.return_value = None
        proc.wait.return_value = 0
        return proc

    monkeypatch.setattr("buddelkiste.features.subprocess.Popen", fake_popen)
    monkeypatch.setattr("buddelkiste.features.time.sleep", fake_sleep)
    try:
        with dbus_proxy_setup() as args:
            assert "DBUS_SESSION_BUS_ADDRESS" in args
    finally:
        for listener in listeners:
            listener.close()


def test_docker_instance_feature_setup_yields_daemon_args(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from contextlib import contextmanager

    seen: list[object] = []

    @contextmanager
    def fake_setup(*, config=None):
        seen.append(config)
        yield ["--setenv", "DOCKER_HOST", "unix:///tmp/instance.sock"]

    monkeypatch.setattr("buddelkiste.cli.load_config", lambda: {"instance": True})
    monkeypatch.setattr("buddelkiste.docker_instance.docker_instance_setup", fake_setup)
    with docker_instance_feature_setup() as args:
        assert list(args) == ["--setenv", "DOCKER_HOST", "unix:///tmp/instance.sock"]
    assert seen == [{"instance": True}]


def _listen_for_agent(monkeypatch: pytest.MonkeyPatch) -> list[socket.socket]:
    """Bind the agent socket on the first wait, so startup sleeps once."""
    listeners: list[socket.socket] = []
    pending: list[str] = []

    def fake_sleep(_seconds: float) -> None:
        if not pending:
            return
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(pending.pop(0))
        listeners.append(listener)

    def fake_popen(args, **_kwargs):
        pending.append(args[3])
        proc = MagicMock()
        proc.poll.return_value = None
        proc.wait.return_value = 0
        return proc

    monkeypatch.setattr("buddelkiste.features.subprocess.Popen", fake_popen)
    monkeypatch.setattr("buddelkiste.features.time.sleep", fake_sleep)
    return listeners


def test_ssh_agent_adds_key_and_stops(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True)
    key = ssh_dir / "sandbox_ed25519"
    key.write_text("priv", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    listeners = _listen_for_agent(monkeypatch)
    added: list[tuple[list[str], dict[str, str]]] = []

    def fake_run(args, env=None, check=False):
        added.append((list(args), dict(env or {})))
        assert check is True
        return MagicMock()

    monkeypatch.setattr("buddelkiste.features.subprocess.run", fake_run)
    try:
        with SshAgent() as agent:
            assert agent.socket is not None
            assert agent.socket.is_socket()
            agent.add_key(key)
        assert added[0][0][:3] == ["ssh-add", "-q", str(key)]
        assert added[0][1]["SSH_AUTH_SOCK"].endswith("/sock")
    finally:
        for listener in listeners:
            listener.close()


def test_ssh_agent_not_running_rejects_add_key() -> None:
    agent = SshAgent()
    with pytest.raises(click.ClickException, match="ssh-agent is not running"):
        agent.add_key(Path("sandbox_ed25519"))
    agent.__exit__(None, None, None)


def test_ssh_agent_startup_failure_terminates_process(
    runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("buddelkiste.features.time.sleep", lambda _t: None)
    proc = MagicMock()
    proc.poll.return_value = 1
    monkeypatch.setattr("buddelkiste.features.subprocess.Popen", lambda *_a, **_k: proc)
    with pytest.raises(click.ClickException, match="ssh-agent exited during startup"), SshAgent():
        pass
    proc.terminate.assert_called_once()


def test_find_sandbox_ssh_key_skips_public_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    assert find_sandbox_ssh_key() is None
    (ssh_dir / "sandbox_ed25519.pub").write_text("pub", encoding="utf-8")
    assert find_sandbox_ssh_key() is None
    private = ssh_dir / "sandbox_ed25519"
    private.write_text("priv", encoding="utf-8")
    assert find_sandbox_ssh_key() == private


def test_ssh_setup_warns_when_no_sandbox_key(
    tmp_path: Path,
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    listeners = _listen_for_agent(monkeypatch)

    def fail_run(*_args, **_kwargs):
        raise AssertionError("ssh-add should not run")

    monkeypatch.setattr("buddelkiste.features.subprocess.run", fail_run)
    try:
        with caplog.at_level(logging.WARNING), ssh_setup() as args:
            assert "SSH_AUTH_SOCK" in args
            sock = args[args.index("SSH_AUTH_SOCK") + 1]
            assert sock.endswith("/sock")
            assert "--ro-bind" in args
        assert "no ~/.ssh/sandbox_* private key" in caplog.text
    finally:
        for listener in listeners:
            listener.close()


def test_ssh_setup_loads_sandbox_key(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True)
    key = ssh_dir / "sandbox_ed25519"
    key.write_text("priv", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    listeners = _listen_for_agent(monkeypatch)
    added: list[str] = []
    monkeypatch.setattr(
        "buddelkiste.features.subprocess.run",
        lambda args, **_kwargs: added.append(args[2]),
    )
    try:
        with ssh_setup() as args:
            assert args[args.index("SSH_AUTH_SOCK") + 1].endswith("/sock")
        assert added == [str(key)]
    finally:
        for listener in listeners:
            listener.close()


class _EntryPoint:
    def __init__(self, name: str, value: str, loaded: object) -> None:
        self.name = name
        self.value = value
        self._loaded = loaded

    def load(self) -> object:
        loaded = self._loaded
        if isinstance(loaded, Exception):
            raise loaded
        return loaded


def _use_entry_points(monkeypatch: pytest.MonkeyPatch, eps: list[_EntryPoint]):
    class _Group:
        def select(self, *, group: str) -> list[_EntryPoint]:
            assert group == ENTRY_POINT_GROUP
            return eps

    monkeypatch.setattr("buddelkiste.features.entry_points", lambda: _Group())
    load_entry_point_features.cache_clear()


def test_entry_points_fallback_when_none_are_registered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_entry_points(monkeypatch, [])
    try:
        loaded = load_entry_point_features()
        assert loaded["cursor"].origin == "buddelkiste.features:CURSOR"
        assert "user" in loaded
        assert feature_names() == list(loaded)
    finally:
        monkeypatch.setattr("buddelkiste.features.entry_points", real_entry_points)
        clear_feature_caches()


def test_entry_point_load_errors_and_factories(monkeypatch: pytest.MonkeyPatch) -> None:
    def factory() -> Feature:
        return Feature(name="ignored", description="Made by a factory")

    _use_entry_points(
        monkeypatch,
        [_EntryPoint("made", "acme:made", factory)],
    )
    try:
        loaded = load_entry_point_features()
        assert loaded["made"].name == "made"
        assert loaded["made"].description == "Made by a factory"
        assert loaded["made"].origin == "acme:made"
    finally:
        monkeypatch.setattr("buddelkiste.features.entry_points", real_entry_points)
        clear_feature_caches()

    _use_entry_points(
        monkeypatch,
        [_EntryPoint("bad", "acme:bad", RuntimeError("missing"))],
    )
    try:
        with pytest.raises(click.ClickException, match="Failed to load feature entry point 'bad'"):
            load_entry_point_features()
    finally:
        monkeypatch.setattr("buddelkiste.features.entry_points", real_entry_points)
        clear_feature_caches()

    _use_entry_points(
        monkeypatch,
        [_EntryPoint("nope", "acme:nope", lambda: "not-a-feature")],
    )
    try:
        with pytest.raises(click.ClickException, match="did not return a Feature"):
            load_entry_point_features()
    finally:
        monkeypatch.setattr("buddelkiste.features.entry_points", real_entry_points)
        clear_feature_caches()

    _use_entry_points(
        monkeypatch,
        [_EntryPoint("obj", "acme:obj", 5)],
    )
    try:
        with pytest.raises(click.ClickException, match="must be a Feature"):
            load_entry_point_features()
    finally:
        monkeypatch.setattr("buddelkiste.features.entry_points", real_entry_points)
        clear_feature_caches()

    first = _EntryPoint("dup", "acme:first", Feature(name="dup", description="First"))
    second = _EntryPoint("dup", "acme:second", Feature(name="dup", description="Second"))
    _use_entry_points(monkeypatch, [first, second])
    try:
        with pytest.raises(click.ClickException, match="Duplicate feature entry point 'dup'"):
            load_entry_point_features()
    finally:
        monkeypatch.setattr("buddelkiste.features.entry_points", real_entry_points)
        clear_feature_caches()


def test_parse_toml_feature_rejects_bad_shapes() -> None:
    with pytest.raises(click.ClickException, match="Invalid feature name"):
        parse_toml_feature("1bad", {})
    with pytest.raises(click.ClickException, match="must be a table"):
        parse_toml_feature("mine", [])  # type: ignore[arg-type]
    with pytest.raises(click.ClickException, match="env must be a list"):
        load_feature_registry({"feature": {"mine": {"env": "FOO"}}})
    with pytest.raises(click.ClickException, match="binds must be a list"):
        load_feature_registry({"feature": {"mine": {"binds": {"source": "/tmp"}}}})
    with pytest.raises(click.ClickException, match="binds\\[0\\] must be a table"):
        load_feature_registry({"feature": {"mine": {"binds": ["nope"]}}})
    with pytest.raises(click.ClickException, match="conflicts_with must be a list"):
        load_feature_registry({"feature": {"mine": {"conflicts_with": "docker"}}})
    with pytest.raises(click.ClickException, match="feature must be a table"):
        load_feature_registry({"feature": ["mine"]})

    feature = parse_toml_feature(
        "mine",
        {"env_vars": ["FOO"], "conflicts_with": ["docker"], "default": True},
    )
    assert feature.env_vars == ("FOO",)
    assert feature.conflicts_with == ("docker",)
    assert feature.default is True
    assert feature.description == "Custom feature 'mine'"


def test_bind_specs_reject_bad_modes_and_require_one_match(tmp_path: Path) -> None:
    with pytest.raises(click.ClickException, match="unknown keys: extra"):
        binds_from_spec({"source": "/tmp", "extra": True})
    with pytest.raises(click.ClickException, match="invalid mode 'overlay:'"):
        binds_from_spec({"source": "/tmp", "mode": "overlay:"})
    with pytest.raises(click.ClickException, match="invalid mode 'sideways'"):
        binds_from_spec({"source": "/tmp", "mode": "sideways"})
    with pytest.raises(click.ClickException, match="binds\\[0\\]"):
        _bind_from_parts("/tmp", None, "nope", where="binds[0]")

    one = tmp_path / "a.txt"
    two = tmp_path / "b.txt"
    one.write_text("a", encoding="utf-8")
    two.write_text("b", encoding="utf-8")
    mounted = binds_from_spec(
        {"glob": str(tmp_path / "*.txt"), "target": str(tmp_path / "mnt"), "mode": "ro"}
    )
    assert {bind.target for bind in mounted} == {
        str(tmp_path / "mnt" / "a.txt"),
        str(tmp_path / "mnt" / "b.txt"),
    }
    with pytest.raises(click.ClickException, match="got 2"):
        bind_from_spec({"glob": str(tmp_path / "*.txt")})
    with pytest.raises(click.ClickException, match="got 0"):
        bind_from_spec({"glob": str(tmp_path / "missing*"), "nullglob": True})
    single = bind_from_spec({"source": str(one), "mode": "rw"})
    assert single.source == str(one)


def test_resolve_features_rejects_non_table_spec() -> None:
    with pytest.raises(click.ClickException, match="Invalid features in config"):
        resolve_features({"features": "git"})


def test_lookup_project_skips_unusable_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    here = tmp_path / "here"
    child = here / "child"
    child.mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    original = Path.resolve

    def resolve(self: Path, *args, **kwargs):
        if self.name == "broken":
            raise OSError("cannot resolve")
        return original(self, *args, **kwargs)

    monkeypatch.setattr("buddelkiste.features.Path.resolve", resolve)
    config = {
        "projects": [
            "skip",
            {"features": {"git": True}},
            {"path": str(tmp_path / "broken"), "features": {"ssh": True}},
            {"path": str(child), "features": {"python": True}},
            {"path": str(here), "features": {"git": True}},
            {"path": str(elsewhere), "features": {"rust": True}},
        ]
    }
    found = lookup_project_config(config, cwd=child)
    assert found is not None
    assert found[0] == child.resolve()
    assert found[1]["features"] == {"python": True}
    assert lookup_project_config({"projects": [{"path": str(elsewhere)}]}, cwd=here) is None
    assert lookup_project_config({"projects": []}, cwd=here) is None
    assert lookup_project_config({"projects": "nope"}, cwd=here) is None


def test_lookup_executable_rejects_relative_dots() -> None:
    config = {
        "executables": {
            "python": {"features": ["git"]},
            "python3": "nope",
        }
    }
    assert lookup_executable_config(config, ".") is None
    assert lookup_executable_config(config, "..") is None
    assert lookup_executable_config(config, "/") is None
    assert lookup_executable_config(config, "") is None
    assert lookup_executable_config(config, None) is None
    assert lookup_executable_config({"executables": ["python"]}, "python") is None
    assert lookup_executable_config(config, "python3") is None
    assert lookup_executable_config(config, "python") == {"features": ["git"]}
